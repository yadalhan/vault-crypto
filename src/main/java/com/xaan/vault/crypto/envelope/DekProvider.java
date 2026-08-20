package com.xaan.vault.crypto.envelope;

import java.util.List;

/**
 * Reads and writes KEK-wrapped DEKs for a service domain. Implementations are
 * responsible only for wrapped-DEK storage; unwrapping is done by {@link KekService}.
 */
public interface DekProvider {

    /** All wrapped DEK versions currently stored for the domain (needed so old data stays decryptable). */
    List<WrappedDek> loadAll(String domain);

    /** The version that new encrypt() calls should use. */
    int loadCurrentVersion(String domain);

    /**
     * Persist a new wrapped DEK version for the domain and mark it current.
     * Existing versions must remain readable after this call.
     */
    void store(String domain, WrappedDek newVersion, int newCurrentVersion);

    /**
     * Permanently removes one DEK version for the domain. Callers must ensure no
     * data still relies on this version (and it must not be the current version)
     * before calling this - it is not reversible.
     */
    void retire(String domain, int version);
}
