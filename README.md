# drocsid-message

A library for creating and verifying cryptographically signed messages.

## Installation

```bash
npm install drocsid-message
```

## Features

- Create and verify message signatures with a dedicated message keypair
- Cryptographically secure wallet-based authorization
- Automatic signature expiration handling
- Tamper-proof message verification

## Usage

### Basic Example

```typescript
import { Keypair } from "@solana/web3.js";
import { createMessageKeypair, signMessage, verifyMessage } from "drocsid-message";
import nacl from "tweetnacl";

// Create a wallet for testing (in production, use your actual wallet)
const walletKeypair = Keypair.generate();
const walletAddress = walletKeypair.publicKey.toBase58();

// Function to sign messages with wallet
const signWithWallet = async (message: Uint8Array): Promise<Uint8Array> => {
  return nacl.sign.detached(message, walletKeypair.secretKey);
};

// Usage flow
async function example() {
  // 1. Create a message keypair (this would typically be stored securely)
  const keypairResult = await createMessageKeypair(signWithWallet, walletAddress);
  
  if (keypairResult.error) {
    console.error("Error creating keypair:", keypairResult.error);
    return;
  }
  
  // 2. Sign a message
  const message = { content: "Hello, World!", timestamp: Date.now() };
  const signedMessage = signMessage(
    message,
    walletAddress,
    new Date().toISOString(),
    keypairResult.messageKeypairPrivateKey,
    keypairResult.authSignature,
    keypairResult.issuedAt,
    keypairResult.expiresAt
  );
  
  // 3. Verify the message
  const verification = verifyMessage(signedMessage);
  
  console.log("Message verification:", verification.valid);
  
  // You can now safely transmit the signedMessage
  // The recipient can verify it without needing the private key
}

example();
```

## API Reference

### Creating a Message Keypair

```typescript
const keypairResult = await createMessageKeypair(
  walletSignFunction, // Function that signs with the wallet
  walletAddress,      // Public address of the wallet
  expirationDays      // Optional: Days until authorization expires (default: 30)
);
```

### Signing Messages

```typescript
const signedMessage = signMessage(
  message,                   // The message object to sign
  walletAddress,             // Wallet address
  createdAt,                 // ISO timestamp of message creation
  messageKeypairPrivateKey,  // Private key of the message keypair
  authSignature,             // Authorization signature
  issuedAt,                  // ISO timestamp when auth was issued
  expiresAt                  // ISO timestamp when auth expires
);
```

### Verifying Messages

```typescript
// Complete verification (both auth and message signature)
const verification = verifyMessage(signedMessage);

// Or verify components separately
const authVerification = verifyKeypairAuth(signedMessage);
const signatureVerification = verifyMessageSignature(signedMessage);
```

## License

ISC 