package com.xaan.vault.crypto.envelope;

import java.security.SecureRandom;

/**
 * Operator-invoked helper for rotating a domain's DEK: generates a new 256-bit key,
 * wraps it with the KEK, and stores it as a new version via the {@link DekProvider}.
 * The previous version is left in place so already-encrypted data keeps decrypting
 * until it is re-encrypted under the new version and retired separately.
 */
public class DekRotationSupport {

    private static final int DEK_LENGTH_BYTES = 32;

    private final KekService kek;
    private final DekProvider dekProvider;

    public DekRotationSupport(KekService kek, DekProvider dekProvider) {
        this.kek = kek;
        this.dekProvider = dekProvider;
    }

    /** Generates and stores a new DEK version for the domain, then returns its version number. */
    public int rotate(String domain) {
        int newVersion = dekProvider.loadCurrentVersion(domain) + 1;

        byte[] plaintextDek = new byte[DEK_LENGTH_BYTES];
        new SecureRandom().nextBytes(plaintextDek);
        byte[] wrapped = kek.wrap(plaintextDek);

        dekProvider.store(domain, new WrappedDek(domain, newVersion, wrapped), newVersion);
        return newVersion;
    }
}
