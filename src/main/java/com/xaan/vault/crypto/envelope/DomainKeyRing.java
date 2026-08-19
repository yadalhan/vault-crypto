package com.xaan.vault.crypto.envelope;

import com.xaan.vault.crypto.CryptoException;
import com.xaan.vault.crypto.KeyLoadingException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * In-memory cache of every unwrapped DEK version for one service domain.
 * Built once (typically at application startup) so that encrypt/decrypt calls
 * on the hot path never need to talk to Vault.
 */
public final class DomainKeyRing {

    private final String domain;
    private final int currentVersion;
    private final Map<Integer, SecretKey> keysByVersion;

    private DomainKeyRing(String domain, int currentVersion, Map<Integer, SecretKey> keysByVersion) {
        this.domain = domain;
        this.currentVersion = currentVersion;
        this.keysByVersion = keysByVersion;
    }

    public static DomainKeyRing load(String domain, KekService kek, DekProvider dekProvider) {
        List<WrappedDek> wrappedDeks = dekProvider.loadAll(domain);
        int currentVersion = dekProvider.loadCurrentVersion(domain);

        Map<Integer, SecretKey> keys = new HashMap<>();
        for (WrappedDek wrapped : wrappedDeks) {
            byte[] plainDek = kek.unwrap(wrapped.wrappedBytes());
            keys.put(wrapped.version(), new SecretKeySpec(plainDek, "AES"));
        }
        if (!keys.containsKey(currentVersion)) {
            throw new KeyLoadingException("Current DEK version " + currentVersion +
                    " not found among loaded DEK versions for domain '" + domain + "'");
        }
        return new DomainKeyRing(domain, currentVersion, Map.copyOf(keys));
    }

    public String domain() {
        return domain;
    }

    public int currentVersion() {
        return currentVersion;
    }

    public SecretKey currentKey() {
        return keysByVersion.get(currentVersion);
    }

    public SecretKey keyFor(int version) {
        SecretKey key = keysByVersion.get(version);
        if (key == null) {
            throw new CryptoException("No DEK version " + version + " loaded for domain '" + domain + "'");
        }
        return key;
    }
}
