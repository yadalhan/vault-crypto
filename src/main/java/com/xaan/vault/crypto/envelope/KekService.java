package com.xaan.vault.crypto.envelope;

import com.xaan.vault.crypto.KeyLoadingException;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.Base64;
import java.util.Map;

/**
 * Loads the Key Encryption Key (KEK) from Vault and uses it only to wrap/unwrap
 * Data Encryption Keys (DEKs) - it never touches application data directly.
 */
public class KekService {

    private final byte[] kekBytes;

    /** For tests or non-Vault key sources; skips the Vault round trip. */
    public KekService(byte[] rawKekBytes) {
        this.kekBytes = rawKekBytes;
    }

    public KekService(VaultOperations vaultOperations, String kekSecretPath) {
        this(vaultOperations, kekSecretPath, "kek");
    }

    public KekService(VaultOperations vaultOperations, String kekSecretPath, String fieldName) {
        this.kekBytes = loadKey(vaultOperations, kekSecretPath, fieldName);
    }

    @SuppressWarnings("unchecked")
    private static byte[] loadKey(VaultOperations vaultOperations, String kekSecretPath, String fieldName) {
        try {
            VaultResponse response = vaultOperations.read(kekSecretPath);
            if (response == null) {
                throw new KeyLoadingException("Vault read returned null response for KEK path " + kekSecretPath);
            }
            Map<String, Object> outerData = response.getData();
            if (outerData == null) {
                throw new KeyLoadingException("Vault response has null data for KEK path " + kekSecretPath);
            }
            Map<String, Object> secretData = (Map<String, Object>) outerData.get("data");
            if (secretData == null) {
                throw new KeyLoadingException("No 'data' field in Vault response for KEK path " + kekSecretPath);
            }
            String kekBase64 = (String) secretData.get(fieldName);
            if (kekBase64 == null || kekBase64.isEmpty()) {
                throw new KeyLoadingException("'" + fieldName + "' not found in Vault secret at " + kekSecretPath);
            }
            return Base64.getUrlDecoder().decode(kekBase64);
        } catch (KeyLoadingException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyLoadingException("Failed to load KEK from Vault: " + e.getMessage(), e);
        }
    }

    /** Wrap (encrypt) a plaintext DEK with the KEK. Returns IV + ciphertext + tag. */
    public byte[] wrap(byte[] plaintextDek) {
        return AesGcmCodec.encrypt(kekBytes, plaintextDek);
    }

    /** Unwrap (decrypt) a KEK-wrapped DEK back to its plaintext bytes. */
    public byte[] unwrap(byte[] wrappedDek) {
        return AesGcmCodec.decrypt(kekBytes, wrappedDek);
    }
}
