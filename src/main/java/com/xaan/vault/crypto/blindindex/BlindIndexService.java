package com.xaan.vault.crypto.blindindex;

import com.xaan.vault.crypto.CryptoException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

/**
 * Computes a deterministic, keyed HMAC-SHA256 "blind index" for a plaintext value, so
 * an application can search for exact matches of a value that's otherwise only stored
 * AES-GCM-encrypted (which, being randomized, never produces the same ciphertext twice
 * and so can't be queried with {@code WHERE column = ?}).
 *
 * <p>The application stores this alongside the encrypted column (e.g. {@code phone} +
 * {@code phone_blind_idx}) and, to search, computes the blind index of the search term
 * the same way and queries {@code WHERE phone_blind_idx = ?}. This only supports exact
 * match, not partial/prefix search - HMAC output has no relationship to the input's
 * structure, by design (that's what makes it safe to store next to the ciphertext).
 *
 * <p>Not tied to {@link com.xaan.vault.crypto.envelope.KekService}/DEKs at all - it's a
 * separate keyed primitive with its own key from {@link BlindIndexKeyProvider}, so that
 * rotating a DEK never silently invalidates existing blind index values (which would
 * require reindexing every row) and vice versa.
 */
public class BlindIndexService {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final SecretKeySpec key;

    private BlindIndexService(byte[] keyBytes) {
        this.key = new SecretKeySpec(keyBytes, HMAC_ALGORITHM);
    }

    /** Loads the named index's key from the provider (typically once, at startup). */
    public static BlindIndexService forIndex(String indexName, BlindIndexKeyProvider provider) {
        return new BlindIndexService(provider.loadKey(indexName));
    }

    /** For tests or a locally-generated key, without going through a provider. */
    public static BlindIndexService withKey(byte[] keyBytes) {
        return new BlindIndexService(keyBytes);
    }

    /**
     * Computes the blind index for a plaintext value. Callers are responsible for any
     * normalization needed before calling this (e.g. stripping formatting characters
     * from a phone number) - the same normalized form must be used consistently at
     * both write time and search time, or lookups will silently never match.
     */
    public String compute(String plainText) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(key);
            byte[] digest = mac.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Failed to compute blind index", e);
        }
    }
}
