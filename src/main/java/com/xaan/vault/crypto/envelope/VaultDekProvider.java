package com.xaan.vault.crypto.envelope;

import com.xaan.vault.crypto.KeyLoadingException;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Stores KEK-wrapped DEKs in Vault KV-v2, one secret per domain at
 * {@code {dekBasePath}/{domain}}. Each secret holds one field per DEK version
 * ({@code dek-v1}, {@code dek-v2}, ...) plus a {@code current-version} pointer,
 * so that old and new DEK versions stay readable across a rotation.
 */
public class VaultDekProvider implements DekProvider {

    private static final String VERSION_FIELD_PREFIX = "dek-v";
    private static final String CURRENT_VERSION_FIELD = "current-version";

    private final VaultOperations vaultOperations;
    private final String dekBasePath;

    public VaultDekProvider(VaultOperations vaultOperations, String dekBasePath) {
        this.vaultOperations = vaultOperations;
        this.dekBasePath = dekBasePath;
    }

    @Override
    public List<WrappedDek> loadAll(String domain) {
        Map<String, Object> secretData = readSecretData(domain);
        List<WrappedDek> result = new ArrayList<>();
        for (Map.Entry<String, Object> entry : secretData.entrySet()) {
            String field = entry.getKey();
            if (field.startsWith(VERSION_FIELD_PREFIX)) {
                int version = Integer.parseInt(field.substring(VERSION_FIELD_PREFIX.length()));
                byte[] wrapped = Base64.getUrlDecoder().decode((String) entry.getValue());
                result.add(new WrappedDek(domain, version, wrapped));
            }
        }
        if (result.isEmpty()) {
            throw new KeyLoadingException("No DEK versions found for domain '" + domain + "' at " + domainPath(domain));
        }
        return result;
    }

    @Override
    public int loadCurrentVersion(String domain) {
        Map<String, Object> secretData = readSecretData(domain);
        Object currentVersion = secretData.get(CURRENT_VERSION_FIELD);
        if (currentVersion == null) {
            throw new KeyLoadingException("No '" + CURRENT_VERSION_FIELD + "' field for domain '" + domain +
                    "' at " + domainPath(domain));
        }
        return Integer.parseInt(currentVersion.toString());
    }

    @Override
    public void store(String domain, WrappedDek newVersion, int newCurrentVersion) {
        Map<String, Object> fields = new LinkedHashMap<>();
        for (WrappedDek existing : loadAll(domain)) {
            fields.put(VERSION_FIELD_PREFIX + existing.version(), encode(existing.wrappedBytes()));
        }
        fields.put(VERSION_FIELD_PREFIX + newVersion.version(), encode(newVersion.wrappedBytes()));
        fields.put(CURRENT_VERSION_FIELD, String.valueOf(newCurrentVersion));

        vaultOperations.write(domainPath(domain), Map.of("data", fields));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readSecretData(String domain) {
        String path = domainPath(domain);
        VaultResponse response = vaultOperations.read(path);
        if (response == null || response.getData() == null) {
            throw new KeyLoadingException("Vault read returned no data for DEK path " + path);
        }
        Map<String, Object> secretData = (Map<String, Object>) response.getData().get("data");
        if (secretData == null) {
            throw new KeyLoadingException("No 'data' field in Vault response for DEK path " + path);
        }
        return secretData;
    }

    private String domainPath(String domain) {
        return dekBasePath + "/" + domain;
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
