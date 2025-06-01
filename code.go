package chatterbox

import (
	"encoding/binary"
	"errors"
)

const HANDSHAKE_CHECK_LABEL byte = 0x11
const ROOT_LABEL = 0x22
const CHAIN_LABEL = 0x33
const KEY_LABEL = 0x44

type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
	LastAction        int
}

type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {
	if session, exists := c.Sessions[*partnerIdentity]; exists {
		session.RootChain.Zeroize()
		session.MyDHRatchet.Zeroize()
		session.SendChain.Zeroize()
		session.ReceiveChain.Zeroize()

		for key, cached := range session.CachedReceiveKeys {
			cached.Zeroize()
			delete(session.CachedReceiveKeys, key)
		}

		delete(c.Sessions, *partnerIdentity)
		return nil
	}
	return errors.New("Session not found")
}

func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {
	if _, active := c.Sessions[*partnerIdentity]; active {
		return nil, errors.New("Session already exists")
	}

	session := &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       GenerateKeyPair(),
	}

	c.Sessions[*partnerIdentity] = session
	return &session.MyDHRatchet.PublicKey, nil
}

func (c *Chatter) ReturnHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {
	if _, active := c.Sessions[*partnerIdentity]; active {
		return nil, nil, errors.New("Session already exists")
	}

	session := &Session{
		MyDHRatchet:       GenerateKeyPair(),
		PartnerDHRatchet:  partnerEphemeral,
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		LastAction:        1,
	}

	session.RootChain = CombineKeys(
		DHCombine(partnerIdentity, &session.MyDHRatchet.PrivateKey),
		DHCombine(partnerEphemeral, &c.Identity.PrivateKey),
		DHCombine(partnerEphemeral, &session.MyDHRatchet.PrivateKey),
	)

	authKey := session.RootChain.DeriveKey(HANDSHAKE_CHECK_LABEL)

	session.ReceiveChain = session.RootChain.DeriveKey(CHAIN_LABEL)
	session.RootChain = session.RootChain.DeriveKey(ROOT_LABEL)
	session.SendChain = session.RootChain

	c.Sessions[*partnerIdentity] = session
	return &session.MyDHRatchet.PublicKey, authKey, nil
}

func (c *Chatter) FinalizeHandshake(partnerIdentity, partnerEphemeral *PublicKey) (*SymmetricKey, error) {
	session, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return nil, errors.New("Session not initiated")
	}

	session.PartnerDHRatchet = partnerEphemeral

	session.RootChain = CombineKeys(
		DHCombine(partnerEphemeral, &c.Identity.PrivateKey),
		DHCombine(partnerIdentity, &session.MyDHRatchet.PrivateKey),
		DHCombine(partnerEphemeral, &session.MyDHRatchet.PrivateKey),
	)

	authKey := session.RootChain.DeriveKey(HANDSHAKE_CHECK_LABEL)

	session.SendChain = session.RootChain
	session.RootChain = session.RootChain.DeriveKey(ROOT_LABEL)
	session.ReceiveChain = session.RootChain

	session.LastUpdate = 1
	return authKey, nil
}

func (c *Chatter) SendMessage(partnerIdentity *PublicKey, plaintext string) (*Message, error) {
	session, exists := c.Sessions[*partnerIdentity]
	if !exists {
		return nil, errors.New("No active session with this partner")
	}

	session.SendCounter++
	message := &Message{
		Sender:   &c.Identity.PublicKey,
		Receiver: partnerIdentity,
		IV:       NewIV(),
		Counter:  session.SendCounter,
	}

	switch session.LastAction {
	case 1:
		oldRoot := session.RootChain
		session.MyDHRatchet = GenerateKeyPair()
		newKey := DHCombine(session.PartnerDHRatchet, &session.MyDHRatchet.PrivateKey)
		session.RootChain = CombineKeys(session.RootChain, newKey)
		session.SendChain = session.RootChain.DeriveKey(CHAIN_LABEL)

		session.LastAction = 0
		session.LastUpdate = session.SendCounter
		oldRoot.Zeroize()

	default:
		oldChain := session.SendChain
		session.SendChain = session.SendChain.DeriveKey(CHAIN_LABEL)
		oldChain.Zeroize()
	}

	message.NextDHRatchet = &session.MyDHRatchet.PublicKey
	message.LastUpdate = session.LastUpdate
	messageKey := session.SendChain.DeriveKey(KEY_LABEL)
	message.Ciphertext = messageKey.AuthenticatedEncrypt(plaintext, message.EncodeAdditionalData(), message.IV)
	messageKey.Zeroize()

	return message, nil
}

func (c *Chatter) ReceiveMessage(message *Message) (string, error) {
	session, exists := c.Sessions[*message.Sender]
	if !exists {
		return "", errors.New("No active session with this sender")
	}

	if message.Counter > session.ReceiveCounter {
		for i := message.Counter - session.ReceiveCounter; i > 0; i-- {
			session.ReceiveCounter++
			cachedKey := session.ReceiveChain.DeriveKey(KEY_LABEL)
			session.CachedReceiveKeys[session.ReceiveCounter] = cachedKey
			session.ReceiveChain = session.ReceiveChain.DeriveKey(CHAIN_LABEL)
		}

		session.ReceiveCounter = message.Counter
	}

	messageKey := session.CachedReceiveKeys[message.Counter]
	if messageKey == nil {
		messageKey = session.ReceiveChain.DeriveKey(KEY_LABEL)
	}

	plaintext, err := messageKey.AuthenticatedDecrypt(message.Ciphertext, message.EncodeAdditionalData(), message.IV)
	if err != nil {
		return "", errors.New("Decryption failed")
	}

	messageKey.Zeroize()
	return plaintext, nil
}
