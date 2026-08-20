package com.xaan.vault.crypto.envelope;

import java.util.Map;

/**
 * Reads and writes versioned KEK material. Implementations are responsible only
 * for KEK storage; wrap/unwrap using the KEK is done by {@link KekService}.
 */
public interface KekProvider {

    /** All KEK versions currently stored, keyed by version number. */
    Map<Integer, byte[]> loadAll();

    /** The version that new wrap() calls should use. */
    int loadCurrentVersion();

    /**
     * Persist a new KEK version and mark it current. Existing versions must
     * remain readable after this call, so already-wrapped DEKs stay unwrappable.
     */
    void store(int newVersion, byte[] newKekBytes, int newCurrentVersion);

    /**
     * Permanently removes one KEK version. Callers must ensure no wrapped DEK
     * still depends on this version (and it must not be the current version)
     * before calling this - it is not reversible.
     */
    void retire(int version);
}
