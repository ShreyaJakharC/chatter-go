# chatterbox-go

## Overview
Chatterbox is a Go-based secure messaging client implementing a Signal-style Double Ratchet (double ratchet) protocol with a Triple Diffie-Hellman (3DH) handshake. It ensures:
- **Confidentiality & Integrity**: All messages are encrypted with AES-GCM.
- **Deniable Session Authentication**: No signatures—either party can plausibly deny having participated.
- **Forward Secrecy (per message)**: Each message uses a fresh symmetric key, and old keys are zeroized.
- **Post-compromise Recovery**: Periodic Diffie-Hellman ratchets prevent a compromised key from decrypting future messages.
- **Out-of-Order Delivery Resiliency**: Cached message keys let you decrypt messages that arrive late or out of order.
- **Error Handling**: Tampered messages are detected via AEAD’s additional-data checks; state is only updated after integrity is confirmed.
- **Full Key Zeroization**: All private keys and ephemeral symmetric keys are securely overwritten as soon as they’re no longer needed.

This implementation was written as part of the “Chatterbox” assignment for CSCI-UA.0480 (Intro to Computer Security, Fall 2024) and covers the entire protocol from handshake through ratcheting and error recovery.

## Tech Stack
- **Language:** Go (1.20+)
- **Cryptography:**  
  - Elliptic Curve P-256 for Diffie-Hellman (built-in Go “crypto/elliptic”)  
  - AES-GCM (Go’s `crypto/aes` & `crypto/cipher`) for authenticated encryption  
  - SHA-256–based HKDF (Go’s `crypto/hmac` & `crypto/sha256`) for key derivation  
- **Testing:**  
  - Go’s `testing` package with multiple vector and stress tests (handshake tests, one-way chat, synchronous/asynchronous chat, error handling)
- **Utilities:**  
  - `encoding/binary` for packing additional data  
  - Standard Go collections (`map[int]*SymmetricKey`) for caching out-of-order message keys

## Features
- **Triple Diffie-Hellman Handshake (3DH)**  
  - Implements `InitiateHandshake()`, `ReturnHandshake()`, and `FinalizeHandshake()`  
  - Authenticates both parties (deniable) by combining `g^a·B`, `g^A·b`, and `g^a·b` in a fixed order  
  - Derives an initial root key and an authentication key (via `DERIVE(HANDSHAKE_CHECK_LABEL)`) for verification  

- **Symmetric Double Ratchet**  
  - After handshake, each side holds a “sending chain” and “receiving chain”  
  - Each message ratchets the sender’s chain key: `chainKey = DeriveKey(chainKey, CHAIN_LABEL)`  
  - Per-message keys are derived with `DeriveKey(chainKey, KEY_LABEL)`, zeroized after use  
  - Supports late messages by caching unused message keys in `CachedReceiveKeys`  

- **Diffie-Hellman Ratchet**  
  - On each side’s turn to send a message, they generate a fresh ephemeral keypair and send the public value in the message (`NextDHRatchet`)  
  - Receiving side computes a new shared secret, updates the root key:  
    ```text
    newRoot = Combine( KDF(oldRoot, ROOT_LABEL), DH(ephemeralReceived, myEphemeralPrivate) )
    ```  
  - Builds a brand-new sending chain from `newRoot` and zeroizes the old root  
  - Guarantees post-compromise recovery: once a new DH ratchet happens, previously compromised chain keys can’t decrypt future messages  

- **Out-of-Order Handling**  
  - When a message arrives with `Counter > ReceiveCounter`, advance the receiving chain as needed to derive each intermediate message key and cache it  
  - Uses `LastUpdate` to know which chain the sender used when ratcheting last  
  - Late messages simply look up the cached key and decrypt without re-ratcheting  

- **Error Detection & Safe State Updates**  
  - AEAD’s associated data (sender fingerprint, receiver fingerprint, next DH ratchet public, counters) is included before encryption  
  - On decryption failure, no state is updated—old chain keys and ratchet state remain intact  
  - Only after successful decryption do we zeroize used keys and update counters  

- **Zeroization of Key Material**  
  - Every `SymmetricKey` and DH private key has an explicit `Zeroize()` call as soon as it’s no longer needed  
  - `EndSession()` securely wipes all chain keys, ratchet keys, and cached keys before deleting the session  
  - Ensures no sensitive key material lingers in memory  

## Key Takeaways
- **Cryptography in Practice**: Building a Signal-style protocol from scratch deepened my understanding of HKDF, AES-GCM, and elliptic-curve Diffie-Hellman.  
- **Double Ratchet Mechanics**: Implementing the symmetric and DH ratchets clarified how forward secrecy and post-compromise recovery work in real time.  
- **Out-of-Order Message Logic**: Handling “early” and “late” messages with cached keys highlighted the complexity of real-world network behavior.  
- **Error-Safe State Management**: Ensuring that state is only mutated after successful decryption (and zeroizing on failure) was crucial to avoid corrupting the ratchet.  
- **Go Best Practices**:  
  - Passing keys by pointer to avoid accidental copies.  
  - Deferring `Zeroize()` calls to guarantee overwrite even on early returns.  
  - Structuring `Session` and `Chatter` types to minimize unintended key duplication in memory.  
- **Testing & Debugging**: The provided test suite (unit tests, handshake vectors, synchronous/asynchronous stress tests) was invaluable for validating each protocol phase—particularly the strict vector tests for handshake and message ordering.

## Quick Start
1. **Clone the repository**  
   ```bash
   git clone https://github.com/your-username/chatterbox-go.git
   cd chatterbox-go
