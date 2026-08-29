package com.xaan.vault.crypto.blindindex;

import com.xaan.vault.crypto.KeyLoadingException;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.Base64;
import java.util.Map;

/**
 * Stores blind-index HMAC keys in Vault KV-v2, one secret per index name at
 * {@code {basePath}/{indexName}} with a single {@code key} field (Base64URL-encoded).
 */
public class VaultBlindIndexKeyProvider implements BlindIndexKeyProvider {

    private static final String KEY_FIELD = "key";

    private final VaultOperations vaultOperations;
    private final String basePath;

    public VaultBlindIndexKeyProvider(VaultOperations vaultOperations, String basePath) {
        this.vaultOperations = vaultOperations;
        this.basePath = basePath;
    }

    @Override
    public byte[] loadKey(String indexName) {
        String path = basePath + "/" + indexName;
        VaultResponse response = vaultOperations.read(path);
        if (response == null || response.getData() == null) {
            throw new KeyLoadingException("Vault read returned no data for blind index path " + path);
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> secretData = (Map<String, Object>) response.getData().get("data");
        if (secretData == null) {
            throw new KeyLoadingException("No 'data' field in Vault response for blind index path " + path);
        }
        Object key = secretData.get(KEY_FIELD);
        if (key == null) {
            throw new KeyLoadingException("No '" + KEY_FIELD + "' field at " + path);
        }
        return Base64.getUrlDecoder().decode((String) key);
    }

    @Override
    public void storeKey(String indexName, byte[] key) {
        String path = basePath + "/" + indexName;
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(key);
        vaultOperations.write(path, Map.of("data", Map.of(KEY_FIELD, encoded)));
    }
}
