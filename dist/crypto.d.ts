/**
 * Signature-related fields that are added to messages when signed
 */
export interface SignatureFields {
    walletAddress: string;
    createdAt: string;
    messageKeypairAddress: string;
    signature: string;
    authSignature: string;
    issuedAt: string;
    expiresAt: string;
}
/**
 * Generic message type that can contain any fields
 */
export type Message<T = Record<string, any>> = T;
/**
 * Signed message type that extends the base message with signature fields
 */
export type SignedMessage<T = Record<string, any>> = T & SignatureFields;
/**
 * Validation result interface for all verification functions
 */
export interface ValidationResult {
    valid: boolean;
    error?: string;
    errorCode?: string;
}
/**
 * Result interface for keypair creation
 */
export interface MessageKeypairResult {
    messageKeypairAddress: string;
    messageKeypairPrivateKey: string;
    authSignature: string;
    expiresAt: string;
    issuedAt: string;
    error?: string;
    errorCode?: string;
}
/**
 * Creates an authorization message for wallet signing
 *
 * @param walletAddress - The wallet address
 * @param messageKeypairAddress - The message keypair's public key (hex string)
 * @param issuedAt - The issued time as ISO string
 * @param expiresAt - The expiration time as ISO string
 * @returns Encoded authorization message
 */
export declare function createAuthMessage(walletAddress: string, messageKeypairAddress: string, issuedAt: string, expiresAt: string): Uint8Array;
/**
 * Creates a message signing keypair
 *
 * @param walletSign - Wallet signing function
 * @param walletAddress - Wallet address
 * @param expirationDays - Keypair validity period in days (default: 30)
 * @returns Promise resolving to message keypair result
 */
export declare function createMessageKeypair(walletSign: (message: Uint8Array) => Promise<Uint8Array>, walletAddress: string, expirationDays?: number): Promise<MessageKeypairResult>;
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
export declare function signMessage<T extends Record<string, any>>(message: T, walletAddress: string, createdAt: string, messageKeypairPrivateKey: string, authSignature: string, issuedAt: string, expiresAt: string): SignedMessage<T>;
/**
 * Verifies the authorization of message keypair
 *
 * @param signedMessage - The signed message to verify
 * @returns Validation result object
 */
export declare function verifyKeypairAuth<T extends Record<string, any>>(signedMessage: SignedMessage<T>): ValidationResult;
/**
 * Verifies the message signature
 *
 * @param signedMessage - The signed message to verify
 * @returns Validation result object
 */
export declare function verifyMessageSignature<T extends Record<string, any>>(signedMessage: SignedMessage<T>): ValidationResult;
/**
 * Performs complete verification of a message (both message signature and authorization signature)
 *
 * @param signedMessage - The signed message to verify
 * @returns Validation result object
 */
export declare function verifyMessage<T extends Record<string, any>>(signedMessage: SignedMessage<T>): ValidationResult;
