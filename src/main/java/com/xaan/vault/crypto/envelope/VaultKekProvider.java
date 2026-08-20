package com.xaan.vault.crypto.envelope;

import com.xaan.vault.crypto.KeyLoadingException;
import org.springframework.vault.core.VaultOperations;
import org.springframework.vault.support.VaultResponse;

import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Stores KEK material in Vault KV-v2 at a single secret path. The secret holds
 * one field per KEK version ({@code kek-v1}, {@code kek-v2}, ...) plus a
 * {@code current-version} pointer, mirroring how {@link VaultDekProvider} stores
 * DEKs - so old KEK versions stay available to unwrap DEKs wrapped under them.
 */
public class VaultKekProvider implements KekProvider {

    private static final String VERSION_FIELD_PREFIX = "kek-v";
    private static final String CURRENT_VERSION_FIELD = "current-version";

    private final VaultOperations vaultOperations;
    private final String kekSecretPath;

    public VaultKekProvider(VaultOperations vaultOperations, String kekSecretPath) {
        this.vaultOperations = vaultOperations;
        this.kekSecretPath = kekSecretPath;
    }

    @Override
    public Map<Integer, byte[]> loadAll() {
        Map<String, Object> secretData = readSecretData();
        Map<Integer, byte[]> result = new HashMap<>();
        for (Map.Entry<String, Object> entry : secretData.entrySet()) {
            String field = entry.getKey();
            if (field.startsWith(VERSION_FIELD_PREFIX)) {
                int version = Integer.parseInt(field.substring(VERSION_FIELD_PREFIX.length()));
                byte[] kekBytes = Base64.getUrlDecoder().decode((String) entry.getValue());
                result.put(version, kekBytes);
            }
        }
        if (result.isEmpty()) {
            throw new KeyLoadingException("No KEK versions found at " + kekSecretPath);
        }
        return result;
    }

    @Override
    public int loadCurrentVersion() {
        Map<String, Object> secretData = readSecretData();
        Object currentVersion = secretData.get(CURRENT_VERSION_FIELD);
        if (currentVersion == null) {
            throw new KeyLoadingException("No '" + CURRENT_VERSION_FIELD + "' field at " + kekSecretPath);
        }
        return Integer.parseInt(currentVersion.toString());
    }

    @Override
    public void store(int newVersion, byte[] newKekBytes, int newCurrentVersion) {
        Map<String, Object> fields = new LinkedHashMap<>();
        for (Map.Entry<Integer, byte[]> existing : loadAll().entrySet()) {
            fields.put(VERSION_FIELD_PREFIX + existing.getKey(), encode(existing.getValue()));
        }
        fields.put(VERSION_FIELD_PREFIX + newVersion, encode(newKekBytes));
        fields.put(CURRENT_VERSION_FIELD, String.valueOf(newCurrentVersion));

        vaultOperations.write(kekSecretPath, Map.of("data", fields));
    }

    @Override
    public void retire(int version) {
        int currentVersion = loadCurrentVersion();
        if (version == currentVersion) {
            throw new IllegalArgumentException("Refusing to retire KEK version " + version + " - it is the current version");
        }

        Map<String, Object> fields = new LinkedHashMap<>();
        for (Map.Entry<Integer, byte[]> existing : loadAll().entrySet()) {
            if (existing.getKey() != version) {
                fields.put(VERSION_FIELD_PREFIX + existing.getKey(), encode(existing.getValue()));
            }
        }
        fields.put(CURRENT_VERSION_FIELD, String.valueOf(currentVersion));

        vaultOperations.write(kekSecretPath, Map.of("data", fields));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readSecretData() {
        VaultResponse response = vaultOperations.read(kekSecretPath);
        if (response == null || response.getData() == null) {
            throw new KeyLoadingException("Vault read returned no data for KEK path " + kekSecretPath);
        }
        Map<String, Object> secretData = (Map<String, Object>) response.getData().get("data");
        if (secretData == null) {
            throw new KeyLoadingException("No 'data' field in Vault response for KEK path " + kekSecretPath);
        }
        return secretData;
    }

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
