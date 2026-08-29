package com.xaan.vault.crypto.blindindex;

/**
 * Storage for a blind-index HMAC key, one per index name (typically one per searchable
 * field, e.g. "user-phone", "user-rrn" - not one per domain, so that rotating or
 * compromising one field's index key never affects another field's).
 *
 * <p>Unlike {@link com.xaan.vault.crypto.envelope.DekProvider}, this is deliberately
 * unversioned: a blind index has no per-row header to carry a version number (it's a
 * single opaque hash value), so changing the key means every existing row's stored
 * index value stops matching newly-computed ones. Rotating a blind-index key is a
 * one-shot "recompute and update every row's index column" operation done in a single
 * pass, not the gradual/lazy re-encryption that {@link com.xaan.vault.crypto.envelope.DekRotationSupport}
 * supports for DEKs - so a single current key per index name is all that's needed here.
 */
public interface BlindIndexKeyProvider {

    /** Loads the HMAC key bytes for the given index name. */
    byte[] loadKey(String indexName);

    /** Stores (or overwrites) the HMAC key bytes for the given index name. */
    void storeKey(String indexName, byte[] key);
}
