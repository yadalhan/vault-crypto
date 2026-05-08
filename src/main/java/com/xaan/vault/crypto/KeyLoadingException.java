package com.xaan.vault.crypto;

/**
 * Exception thrown when there is an error loading the encryption key from Vault.
 */
public class KeyLoadingException extends CryptoException {
    public KeyLoadingException(String message) {
        super(message);
    }
    
    public KeyLoadingException(String message, Throwable cause) {
        super(message, cause);
    }
}