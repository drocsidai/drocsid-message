import { expect } from 'chai';
import nacl from 'tweetnacl';
import { Keypair } from "@solana/web3.js";
import {
  createAuthMessage,
  createMessageKeypair,
  signMessage,
  verifyKeypairAuth,
  verifyMessageSignature,
  verifyMessage,
  SignedMessage
} from '../src/crypto';

describe('Crypto Module Tests', () => {
  // Setup test wallet using Solana Keypair
  const testKeypair = Keypair.generate();
  const testWalletAddress = testKeypair.publicKey.toBase58();
  
  // Mock wallet signing function
  const mockSignMessage = async (message: Uint8Array): Promise<Uint8Array> => {
    return nacl.sign.detached(message, testKeypair.secretKey);
  };

  // Test message
  const testMessage = {
    content: "This is a test message",
    additionalData: 123
  };

  // Test variables that will be used across tests
  let messageKeypairPrivateKey: string;
  let messageKeypairAddress: string;
  let authSignature: string;
  let issuedAt: string;
  let expiresAt: string;
  let signedMessage: SignedMessage;

  describe('createAuthMessage()', () => {
    it('should create a valid authorization message', () => {
      // Setup
      const walletAddress = testWalletAddress;
      const messageKeypairAddress = Buffer.from(nacl.sign.keyPair().publicKey).toString('hex');
      const issuedAt = new Date().toISOString();
      const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
      
      // Act
      const authMessage = createAuthMessage(walletAddress, messageKeypairAddress, issuedAt, expiresAt);
      
      // Assert
      expect(authMessage).to.be.an.instanceOf(Uint8Array);
      
      // Decode to string to check content
      const decodedMessage = new TextDecoder().decode(authMessage);
      expect(decodedMessage).to.include(walletAddress);
      expect(decodedMessage).to.include(messageKeypairAddress);
      expect(decodedMessage).to.include(issuedAt);
      expect(decodedMessage).to.include(expiresAt);
      expect(decodedMessage).to.include('app://message-signing wants you to sign in with your Solana account');
    });
  });

  describe('createMessageKeypair()', () => {
    it('should create a valid message keypair', async () => {
      // Act
      const result = await createMessageKeypair(mockSignMessage, testWalletAddress);
      
      // Store for other tests
      messageKeypairPrivateKey = result.messageKeypairPrivateKey;
      messageKeypairAddress = result.messageKeypairAddress;
      authSignature = result.authSignature;
      issuedAt = result.issuedAt;
      expiresAt = result.expiresAt;
      
      // Assert
      expect(result.messageKeypairAddress).to.be.a('string').and.not.empty;
      expect(result.messageKeypairPrivateKey).to.be.a('string').and.not.empty;
      expect(result.authSignature).to.be.a('string').and.not.empty;
      expect(result.issuedAt).to.be.a('string').and.not.empty;
      expect(result.expiresAt).to.be.a('string').and.not.empty;
      expect(result.error).to.be.undefined;
      expect(result.errorCode).to.be.undefined;
      
      // Verify the keypair is valid by checking that it has 32 bytes for public key and 64 for private key
      const privateKeyBytes = Buffer.from(result.messageKeypairPrivateKey, 'hex');
      expect(privateKeyBytes.length).to.equal(64);
      
      // The public key should be the last 32 bytes of the private key in nacl
      const extractedPublicKey = privateKeyBytes.slice(32, 64);
      expect(Buffer.from(extractedPublicKey).toString('hex')).to.equal(result.messageKeypairAddress);
    });

    it('should handle errors during keypair creation', async () => {
      // Setup - function that throws an error
      const errorSigningFunction = async () => {
        throw new Error('Test error');
      };
      
      // Act
      const result = await createMessageKeypair(errorSigningFunction, testWalletAddress);
      
      // Assert
      expect(result.messageKeypairAddress).to.equal('');
      expect(result.messageKeypairPrivateKey).to.equal('');
      expect(result.authSignature).to.equal('');
      expect(result.issuedAt).to.equal('');
      expect(result.expiresAt).to.equal('');
      expect(result.error).to.equal('Test error');
      expect(result.errorCode).to.equal('KEYPAIR_CREATION_ERROR');
    });
  });

  describe('signMessage()', () => {
    it('should sign a message and add signature fields', () => {
      // Setup
      const createdAt = new Date().toISOString();
      
      // Act
      signedMessage = signMessage(
        testMessage,
        testWalletAddress,
        createdAt,
        messageKeypairPrivateKey,
        authSignature,
        issuedAt,
        expiresAt
      );
      
      // Assert
      expect(signedMessage).to.include(testMessage);
      expect(signedMessage.signature).to.be.a('string').and.not.empty;
      expect(signedMessage.walletAddress).to.equal(testWalletAddress);
      expect(signedMessage.createdAt).to.equal(createdAt);
      expect(signedMessage.messageKeypairAddress).to.equal(messageKeypairAddress);
      expect(signedMessage.authSignature).to.equal(authSignature);
      expect(signedMessage.issuedAt).to.equal(issuedAt);
      expect(signedMessage.expiresAt).to.equal(expiresAt);
    });
  });

  describe('verifyKeypairAuth()', () => {
    it('should successfully verify a valid authorization signature', () => {
      // Act
      const result = verifyKeypairAuth(signedMessage);
      
      // Assert
      expect(result.valid).to.be.true;
      expect(result.error).to.be.undefined;
      expect(result.errorCode).to.be.undefined;
    });

    it('should fail verification for missing required fields', () => {
      // Test missing authSignature
      const missingAuthSig = { ...signedMessage, authSignature: '' };
      expect(verifyKeypairAuth(missingAuthSig).valid).to.be.false;
      expect(verifyKeypairAuth(missingAuthSig).errorCode).to.equal('MISSING_AUTH_SIGNATURE');
      
      // Test missing messageKeypairAddress
      const missingKeypairAddr = { ...signedMessage, messageKeypairAddress: '' };
      expect(verifyKeypairAuth(missingKeypairAddr).valid).to.be.false;
      expect(verifyKeypairAuth(missingKeypairAddr).errorCode).to.equal('MISSING_KEYPAIR_ADDRESS');
      
      // Test missing expiresAt
      const missingExpiresAt = { ...signedMessage, expiresAt: '' };
      expect(verifyKeypairAuth(missingExpiresAt).valid).to.be.false;
      expect(verifyKeypairAuth(missingExpiresAt).errorCode).to.equal('MISSING_EXPIRES_AT');
      
      // Test missing createdAt
      const missingCreatedAt = { ...signedMessage, createdAt: '' };
      expect(verifyKeypairAuth(missingCreatedAt).valid).to.be.false;
      expect(verifyKeypairAuth(missingCreatedAt).errorCode).to.equal('MISSING_CREATED_AT');
      
      // Test missing walletAddress
      const missingWalletAddr = { ...signedMessage, walletAddress: '' };
      expect(verifyKeypairAuth(missingWalletAddr).valid).to.be.false;
      expect(verifyKeypairAuth(missingWalletAddr).errorCode).to.equal('MISSING_WALLET_ADDRESS');
    });

    it('should fail verification for expired authorization', () => {
      // Setup - expired signature
      const expiredSignature = { 
        ...signedMessage, 
        expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() 
      };
      
      // Act
      const result = verifyKeypairAuth(expiredSignature);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('AUTH_EXPIRED');
    });

    it('should fail verification for invalid wallet address format', () => {
      // Setup - invalid wallet address
      const invalidWalletAddr = { ...signedMessage, walletAddress: 'invalid-address' };
      
      // Act
      const result = verifyKeypairAuth(invalidWalletAddr);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('INVALID_WALLET_ADDRESS');
    });

    it('should fail verification for invalid auth signature', () => {
      // Setup - tampered auth signature
      const tamperedAuthSig = { 
        ...signedMessage, 
        authSignature: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' 
      };
      
      // Act
      const result = verifyKeypairAuth(tamperedAuthSig);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('AUTH_VALIDATION_ERROR');
    });
  });

  describe('verifyMessageSignature()', () => {
    it('should successfully verify a valid message signature', () => {
      // Act
      const result = verifyMessageSignature(signedMessage);
      
      // Assert
      expect(result.valid).to.be.true;
      expect(result.error).to.be.undefined;
      expect(result.errorCode).to.be.undefined;
    });
    
    it('should fail verification for missing signature', () => {
      // Setup - missing signature
      const missingSignature = { ...signedMessage, signature: '' };
      
      // Act
      const result = verifyMessageSignature(missingSignature);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('MISSING_SIGNATURE');
    });
    
    it('should fail verification for missing messageKeypairAddress', () => {
      // Setup - missing messageKeypairAddress
      const missingKeypairAddr = { ...signedMessage, messageKeypairAddress: '' };
      
      // Act
      const result = verifyMessageSignature(missingKeypairAddr);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('MISSING_KEYPAIR_ADDRESS');
    });
    
    it('should fail verification for missing authSignature', () => {
      // Setup - missing authSignature
      const missingAuthSig = { ...signedMessage, authSignature: '' };
      
      // Act
      const result = verifyMessageSignature(missingAuthSig);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('MISSING_AUTH_SIGNATURE');
    });
    
    it('should fail verification for missing expiresAt', () => {
      // Setup - missing expiresAt
      const missingExpiresAt = { ...signedMessage, expiresAt: '' };
      
      // Act
      const result = verifyMessageSignature(missingExpiresAt);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('MISSING_EXPIRES_AT');
    });
    
    it('should fail verification for expired signature', () => {
      // Setup - expired signature
      const expiredSignature = { 
        ...signedMessage, 
        expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() 
      };
      
      // Act
      const result = verifyMessageSignature(expiredSignature);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('SIGNATURE_EXPIRED');
    });
    
    it('should fail verification for tampered message', () => {
      // Setup - tampered message content
      const tamperedMessage = {
        ...signedMessage,
        content: "This message has been tampered with"
      };
      
      // Act
      const result = verifyMessageSignature(tamperedMessage);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('INVALID_SIGNATURE');
    });
  });

  describe('verifyMessage()', () => {
    it('should verify both auth and message signatures for valid messages', () => {
      // Act
      const result = verifyMessage(signedMessage);
      
      // Assert
      expect(result.valid).to.be.true;
      expect(result.error).to.be.undefined;
      expect(result.errorCode).to.be.undefined;
    });
    
    it('should fail when auth signature verification fails', () => {
      // Setup - invalid auth signature
      const invalidAuthSig = { 
        ...signedMessage, 
        authSignature: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' 
      };
      
      // Act
      const result = verifyMessage(invalidAuthSig);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('AUTH_VALIDATION_ERROR');
    });
    
    it('should fail when message signature verification fails', () => {
      // Create a new signedMessage with valid auth but tampered content
      // We need to create a valid message first with all signatures
      const validSignedMessage = signMessage(
        testMessage,
        testWalletAddress,
        new Date().toISOString(),
        messageKeypairPrivateKey,
        authSignature,
        issuedAt,
        expiresAt
      );
      
      // Now tamper with the content but keep the original auth signature
      const tamperedMessage = {
        ...validSignedMessage,
        content: "This message has been tampered with"
      };
      
      // Act
      const result = verifyMessage(tamperedMessage);
      
      // Assert
      expect(result.valid).to.be.false;
      expect(result.errorCode).to.equal('INVALID_SIGNATURE');
    });
  });
}); 