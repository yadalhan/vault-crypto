package com.xaan.vault.crypto;

import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.nio.charset.StandardCharsets;

/**
 * Vault-based encryption/decryption service.
 * Reads encryption key from HashiCorp Vault and provides encrypt/decrypt methods.
 */
@Service
public class VaultCryptoService {

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits recommended for GCM
    private final VaultOperations vaultOperations;
    private byte[] encryptionKey;
    private final String vaultSecretPath;

    /**
     * Create VaultCryptoService with custom Vault secret path.
     * @param vaultOperations Vault operations
     * @param vaultSecretPath Path to secret (e.g., "ebiz_service/data/ebiz_db/data-enc-key")
     */
    public VaultCryptoService(VaultOperations vaultOperations, String vaultSecretPath) {
        this.vaultOperations = vaultOperations;
        this.vaultSecretPath = vaultSecretPath;
        loadEncryptionKey();
    }

    /**
     * Create VaultCryptoService with default secret path.
     * @param vaultOperations Vault operations
     */
    public VaultCryptoService(VaultOperations vaultOperations) {
        this(vaultOperations, "ebiz_service/data/ebiz_db/data-enc-key");
    }

    private void loadEncryptionKey() {
        try {
            VaultResponse response = vaultOperations.read(vaultSecretPath);
            if (response == null) {
                throw new KeyLoadingException("Vault read returned null response");
            }
            Map<String, Object> outerData = response.getData();
            if (outerData == null) {
                throw new KeyLoadingException("Vault response has null data");
            }
            Map<String, Object> secretData = (Map<String, Object>) outerData.get("data");
            if (secretData == null) {
                throw new KeyLoadingException("No 'data' field in Vault response");
            }
            String fernetKeyBase64 = (String) secretData.get("fernet-key");
            if (fernetKeyBase64 == null || fernetKeyBase64.isEmpty()) {
                throw new KeyLoadingException("fernet-key not found in Vault secret");
            }
            this.encryptionKey = Base64.getUrlDecoder().decode(fernetKeyBase64);
        } catch (Exception e) {
            throw new KeyLoadingException("Failed to load encryption key from Vault: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypt plaintext using AES-256 GCM mode.
     * @param plainText Text to encrypt
     * @return Base64 URL-safe encoded string containing IV + ciphertext + tag
     */
    public String encrypt(String plainText) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey, "AES");
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            
            // Generate random IV
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(
                    GCM_TAG_LENGTH_BITS, iv));
            
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            
            // Combine IV + encrypted data for storage (tag is included in the ciphertext buffer with GCM)
            ByteBuffer buffer = ByteBuffer.allocate(
                    iv.length + encryptedBytes.length);
            buffer.put(iv);
            buffer.put(encryptedBytes);
            
            return Base64.getUrlEncoder().encodeToString(buffer.array());
        } catch (Exception e) {
            throw new CryptoException("Error encrypting data", e);
        }
    }

    /**
     * Decrypt encrypted text.
     * @param encryptedText Base64 URL-safe encoded string containing IV + ciphertext
     * @return Decrypted plaintext
     */
    public String decrypt(String encryptedText) {
        try {
            byte[] combined = Base64.getUrlDecoder().decode(encryptedText);
            
            if (combined.length < GCM_IV_LENGTH_BYTES + GCM_TAG_LENGTH_BITS / 8) {
                throw new CryptoException("Encrypted text too short: expected at least " +
                        (GCM_IV_LENGTH_BYTES + GCM_TAG_LENGTH_BITS / 8) + " bytes, got " + combined.length);
            }
            
            ByteBuffer buffer = ByteBuffer.wrap(combined);
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            buffer.get(iv);
            byte[] encryptedBytes = new byte[buffer.remaining()];
            buffer.get(encryptedBytes);
            
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey, "AES");
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(
                    GCM_TAG_LENGTH_BITS, iv));
            
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Error decrypting data", e);
        }
    }

    /**
     * Validate input against stored encrypted value using constant-time comparison.
     * @param input Plaintext input
     * @param storedEncrypted Stored encrypted value
     * @return true if input matches stored value
     */
    public boolean validate(String input, String storedEncrypted) {
        try {
            String decrypted = decrypt(storedEncrypted);
            return MessageDigest.isEqual(
                    decrypted.getBytes(StandardCharsets.UTF_8),
                    input.getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            // If decryption fails, still do constant-time comparison with dummy data
            // to avoid leaking information via timing
            byte[] dummy = new byte[16]; // reasonable password length assumption
            MessageDigest.isEqual(dummy, input.getBytes(StandardCharsets.UTF_8));
            return false;
        }
    }
}
