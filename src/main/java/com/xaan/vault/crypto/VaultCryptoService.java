package com.xaan.vault.crypto;

import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * Vault-based encryption/decryption service.
 * Reads encryption key from HashiCorp Vault and provides encrypt/decrypt methods.
 */
@Service
public class VaultCryptoService {

    private static final String AES_ALGORITHM = "AES";
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
                throw new RuntimeException("Vault read returned null response");
            }
            Map<String, Object> outerData = response.getData();
            if (outerData == null) {
                throw new RuntimeException("Vault response has null data");
            }
            Map<String, Object> secretData = (Map<String, Object>) outerData.get("data");
            if (secretData == null) {
                throw new RuntimeException("No 'data' field in Vault response");
            }
            String fernetKeyBase64 = (String) secretData.get("fernet-key");
            if (fernetKeyBase64 == null || fernetKeyBase64.isEmpty()) {
                throw new RuntimeException("fernet-key not found in Vault secret");
            }
            this.encryptionKey = Base64.getUrlDecoder().decode(fernetKeyBase64);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load encryption key from Vault: " + e.getMessage(), e);
        }
    }

    /**
     * Encrypt plaintext using AES-256 (ECB mode).
     * @param plainText Text to encrypt
     * @return Base64 encoded encrypted string
     */
    public String encrypt(String plainText) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey, AES_ALGORITHM);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    /**
     * Decrypt encrypted text.
     * @param encryptedText Base64 encoded encrypted string
     * @return Decrypted plaintext
     */
    public String decrypt(String encryptedText) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(encryptionKey, AES_ALGORITHM);
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }

    /**
     * Validate input against stored encrypted value.
     * @param input Plaintext input
     * @param storedEncrypted Stored encrypted value
     * @return true if input matches stored value
     */
    public boolean validate(String input, String storedEncrypted) {
        String decrypted = decrypt(storedEncrypted);
        return input.equals(decrypted);
    }
}
