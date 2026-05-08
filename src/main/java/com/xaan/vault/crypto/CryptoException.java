package com.xaan.vault.crypto;

/**
 * Base exception for all vault-crypto related errors.
 */
public class CryptoException extends RuntimeException {
    public CryptoException(String message) {
        super(message);
    }
    
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}