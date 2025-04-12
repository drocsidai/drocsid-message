"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthMessage = createAuthMessage;
exports.createMessageKeypair = createMessageKeypair;
exports.signMessage = signMessage;
exports.verifyKeypairAuth = verifyKeypairAuth;
exports.verifyMessageSignature = verifyMessageSignature;
exports.verifyMessage = verifyMessage;
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const bs58_1 = __importDefault(require("bs58"));
/**
 * Creates an authorization message for wallet signing
 *
 * @param walletAddress - The wallet address
 * @param messageKeypairAddress - The message keypair's public key (hex string)
 * @param issuedAt - The issued time as ISO string
 * @param expiresAt - The expiration time as ISO string
 * @returns Encoded authorization message
 */
function createAuthMessage(walletAddress, messageKeypairAddress, issuedAt, expiresAt) {
    const authMessage = new TextEncoder().encode(`app://message-signing wants you to sign in with your Solana account:
${walletAddress}

Chain ID: 900
Nonce: ${messageKeypairAddress}
Issued At: ${issuedAt}
Expiration Time: ${expiresAt}`);
    return authMessage;
}
/**
 * Creates a message signing keypair
 *
 * @param walletSign - Wallet signing function
 * @param walletAddress - Wallet address
 * @param expirationDays - Keypair validity period in days (default: 30)
 * @returns Promise resolving to message keypair result
 */
async function createMessageKeypair(walletSign, walletAddress, expirationDays = 30) {
    try {
        // Generate a dedicated message signing keypair
        const messageKeypair = tweetnacl_1.default.sign.keyPair();
        const messagePublicKeyHex = Buffer.from(messageKeypair.publicKey).toString('hex');
        // Calculate expiration time
        const now = Date.now();
        const expirationTime = now + (expirationDays * 24 * 60 * 60 * 1000);
        const issuedAt = new Date(now).toISOString();
        const expiresAt = new Date(expirationTime).toISOString();
        // Create authorization message
        const authMessage = createAuthMessage(walletAddress, messagePublicKeyHex, issuedAt, expiresAt);
        // Sign with wallet function
        const signature = await walletSign(authMessage);
        return {
            messageKeypairAddress: messagePublicKeyHex,
            messageKeypairPrivateKey: Buffer.from(messageKeypair.secretKey).toString('hex'),
            authSignature: Buffer.from(signature).toString('hex'),
            issuedAt,
            expiresAt,
        };
    }
    catch (error) {
        return {
            messageKeypairAddress: '',
            messageKeypairPrivateKey: '',
            authSignature: '',
            issuedAt: '',
            expiresAt: '',
            error: error instanceof Error ? error.message : "Unknown error",
            errorCode: "KEYPAIR_CREATION_ERROR"
        };
    }
}
/**
 * Signs a message with a message keypair
 *
 * @param message - Any message object to sign
 * @param walletAddress - The wallet address
 * @param createdAt - Message creation time (ISO string)
 * @param messageKeypairPrivateKey - Message keypair private key (hex)
 * @param authSignature - Authorization signature (hex)
 * @param expiresAt - Signature expiration time (ISO string)
 * @returns Signed message with signature fields
 */
function signMessage(message, walletAddress, createdAt, messageKeypairPrivateKey, authSignature, issuedAt, expiresAt) {
    // 1. Convert hex private key to byte array
    const privateKeyBytes = new Uint8Array(Buffer.from(messageKeypairPrivateKey, 'hex'));
    // 2. Extract public key from private key
    const publicKeyBytes = privateKeyBytes.slice(32, 64);
    const messageKeypairAddress = Buffer.from(publicKeyBytes).toString('hex');
    // 3. Convert message to stable string representation
    const stableString = JSON.stringify(message, Object.keys(message).sort());
    const messageBytes = new TextEncoder().encode(stableString);
    // 4. Sign message
    const signatureBytes = tweetnacl_1.default.sign.detached(messageBytes, privateKeyBytes);
    const signature = Buffer.from(signatureBytes).toString('hex');
    // 5. Return original message with signature fields
    return {
        ...message,
        walletAddress,
        createdAt,
        messageKeypairAddress,
        signature,
        authSignature,
        issuedAt,
        expiresAt,
    };
}
/**
 * Verifies the authorization of message keypair
 *
 * @param signedMessage - The signed message to verify
 * @returns Validation result object
 */
function verifyKeypairAuth(signedMessage) {
    try {
        // 1. Check required fields
        if (!signedMessage.authSignature) {
            return { valid: false, error: "Missing authorization signature", errorCode: "MISSING_AUTH_SIGNATURE" };
        }
        if (!signedMessage.messageKeypairAddress) {
            return { valid: false, error: "Missing message keypair address", errorCode: "MISSING_KEYPAIR_ADDRESS" };
        }
        if (!signedMessage.expiresAt) {
            return { valid: false, error: "Missing expiration time", errorCode: "MISSING_EXPIRES_AT" };
        }
        if (!signedMessage.createdAt) {
            return { valid: false, error: "Missing creation time", errorCode: "MISSING_CREATED_AT" };
        }
        if (!signedMessage.walletAddress) {
            return { valid: false, error: "Missing wallet address", errorCode: "MISSING_WALLET_ADDRESS" };
        }
        // 2. Check if expired
        if (new Date(signedMessage.expiresAt) < new Date(signedMessage.createdAt)) {
            return { valid: false, error: "Authorization has expired", errorCode: "AUTH_EXPIRED" };
        }
        // 3. Determine issue time (backtrack 30 days)
        const expiresAt = signedMessage.expiresAt;
        const issuedAt = signedMessage.issuedAt;
        // 4. Create authorization message
        const authMessage = createAuthMessage(signedMessage.walletAddress, signedMessage.messageKeypairAddress, issuedAt, expiresAt);
        // 5. Convert hex authorization signature to byte array
        const authSignatureBytes = new Uint8Array(Buffer.from(signedMessage.authSignature, 'hex'));
        // 6. Convert wallet address to public key byte array
        let publicKeyBytes;
        try {
            publicKeyBytes = bs58_1.default.decode(signedMessage.walletAddress);
        }
        catch (error) {
            return { valid: false, error: "Invalid wallet address format", errorCode: "INVALID_WALLET_ADDRESS" };
        }
        // 7. Verify signature
        const isAuthSignatureValid = tweetnacl_1.default.sign.detached.verify(authMessage, authSignatureBytes, publicKeyBytes);
        if (!isAuthSignatureValid) {
            return { valid: false, error: "Authorization signature verification failed", errorCode: "INVALID_AUTH_SIGNATURE" };
        }
        // Verification passed
        return { valid: true };
    }
    catch (error) {
        return {
            valid: false,
            error: error instanceof Error ? error.message : "Error verifying authorization signature",
            errorCode: "AUTH_VALIDATION_ERROR"
        };
    }
}
/**
 * Verifies the message signature
 *
 * @param signedMessage - The signed message to verify
 * @returns Validation result object
 */
function verifyMessageSignature(signedMessage) {
    try {
        // 1. Check required fields
        if (!signedMessage.signature) {
            return { valid: false, error: "Missing signature", errorCode: "MISSING_SIGNATURE" };
        }
        if (!signedMessage.messageKeypairAddress) {
            return { valid: false, error: "Missing message keypair address", errorCode: "MISSING_KEYPAIR_ADDRESS" };
        }
        // 2. Check authorization signature and expiration time
        if (!signedMessage.authSignature) {
            return { valid: false, error: "Missing authorization signature", errorCode: "MISSING_AUTH_SIGNATURE" };
        }
        if (!signedMessage.expiresAt) {
            return { valid: false, error: "Missing expiration time", errorCode: "MISSING_EXPIRES_AT" };
        }
        // 3. Check if expired
        if (new Date(signedMessage.expiresAt) < new Date(signedMessage.createdAt)) {
            return { valid: false, error: "Message signature has expired", errorCode: "SIGNATURE_EXPIRED" };
        }
        // 4. Extract base message portion for verification
        const { messageKeypairAddress, signature, authSignature, expiresAt, walletAddress, createdAt, issuedAt, ...message } = signedMessage;
        // 5. Create same message string as during signing
        const stableString = JSON.stringify(message, Object.keys(message).sort());
        // 6. Convert string to byte array
        const messageBytes = new TextEncoder().encode(stableString);
        // 7. Convert signature and public key to byte arrays
        const signatureBytes = new Uint8Array(Buffer.from(signedMessage.signature, 'hex'));
        const publicKeyBytes = new Uint8Array(Buffer.from(signedMessage.messageKeypairAddress, 'hex'));
        // 8. Verify message signature
        const isSignatureValid = tweetnacl_1.default.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
        if (!isSignatureValid) {
            return { valid: false, error: "Message signature verification failed", errorCode: "INVALID_SIGNATURE" };
        }
        // Verification passed
        return { valid: true };
    }
    catch (error) {
        return {
            valid: false,
            error: error instanceof Error ? error.message : "Error verifying message",
            errorCode: "VALIDATION_ERROR"
        };
    }
}
/**
 * Performs complete verification of a message (both message signature and authorization signature)
 *
 * @param signedMessage - The signed message to verify
 * @returns Validation result object
 */
function verifyMessage(signedMessage) {
    // First verify authorization signature
    const authResult = verifyKeypairAuth(signedMessage);
    if (!authResult.valid) {
        return authResult;
    }
    // Then verify message signature
    return verifyMessageSignature(signedMessage);
}
