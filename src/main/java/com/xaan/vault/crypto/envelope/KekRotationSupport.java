package com.xaan.vault.crypto.envelope;

import java.security.SecureRandom;

/**
 * Operator-invoked helper for rotating the KEK. Rotation is two steps, run
 * separately on purpose: (1) issue a new KEK version so both old and new are
 * available, then (2) re-wrap every domain's DEKs under the new version once a
 * {@link KekService} holding both versions has been rebuilt. Old KEK versions
 * are retired (via {@link KekProvider#retire(int)}) only after every domain has
 * been confirmed re-wrapped - see the rotation runbook for the full procedure.
 */
public class KekRotationSupport {

    private static final int KEK_LENGTH_BYTES = 32;

    private final KekProvider kekProvider;

    public KekRotationSupport(KekProvider kekProvider) {
        this.kekProvider = kekProvider;
    }

    /** Generates a new KEK version and stores it as current. Previous versions remain loadable. */
    public int issueNewKekVersion() {
        int newVersion = kekProvider.loadCurrentVersion() + 1;

        byte[] newKek = new byte[KEK_LENGTH_BYTES];
        new SecureRandom().nextBytes(newKek);

        kekProvider.store(newVersion, newKek, newVersion);
        return newVersion;
    }

    /**
     * Re-wraps every stored DEK version of one domain under {@code kekRing}'s current KEK
     * version. {@code kekRing} must already have every KEK version those DEKs were
     * originally wrapped under loaded (to unwrap), plus the new current version (to re-wrap).
     * The DEK version numbers and the domain's current-DEK-version pointer are unchanged -
     * only which KEK version protects each DEK changes.
     */
    public void rewrapDomainDeks(KekService kekRing, DekProvider dekProvider, String domain) {
        int currentDekVersion = dekProvider.loadCurrentVersion(domain);
        for (WrappedDek wrapped : dekProvider.loadAll(domain)) {
            byte[] plainDek = kekRing.unwrap(wrapped.wrappedBytes());
            byte[] rewrapped = kekRing.wrap(plainDek);
            dekProvider.store(domain, new WrappedDek(domain, wrapped.version(), rewrapped), currentDekVersion);
        }
    }
}
