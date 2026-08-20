package com.xaan.vault.crypto.envelope;

import com.xaan.vault.crypto.CryptoException;
import com.xaan.vault.crypto.KeyLoadingException;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;

/**
 * Holds every loaded KEK version and uses them only to wrap/unwrap Data Encryption
 * Keys (DEKs) - it never touches application data directly. Wrapped-DEK bytes are
 * self-describing: {@code kekVersion(1B) | IV(12B) | ciphertext+tag}, so unwrap()
 * picks the right KEK version even after a rotation, as long as that version is
 * still loaded.
 */
public class KekService {

    private final Map<Integer, byte[]> kekByVersion;
    private final int currentVersion;

    /** For tests or a single non-versioned key; treated as version 1. */
    public KekService(byte[] rawKekBytes) {
        this(Map.of(1, rawKekBytes), 1);
    }

    public KekService(Map<Integer, byte[]> kekByVersion, int currentVersion) {
        if (!kekByVersion.containsKey(currentVersion)) {
            throw new KeyLoadingException("Current KEK version " + currentVersion +
                    " not found among loaded KEK versions " + kekByVersion.keySet());
        }
        this.kekByVersion = Map.copyOf(kekByVersion);
        this.currentVersion = currentVersion;
    }

    public static KekService load(KekProvider kekProvider) {
        return new KekService(kekProvider.loadAll(), kekProvider.loadCurrentVersion());
    }

    public int currentVersion() {
        return currentVersion;
    }

    /** Wrap (encrypt) a plaintext DEK with the current KEK version. Returns kekVersion + IV + ciphertext + tag. */
    public byte[] wrap(byte[] plaintextDek) {
        byte[] kek = kekByVersion.get(currentVersion);
        byte[] ivCiphertextTag = AesGcmCodec.encrypt(kek, plaintextDek);

        ByteBuffer buffer = ByteBuffer.allocate(1 + ivCiphertextTag.length);
        buffer.put((byte) currentVersion);
        buffer.put(ivCiphertextTag);
        return buffer.array();
    }

    /** Unwrap (decrypt) a KEK-wrapped DEK back to its plaintext bytes, using the KEK version recorded in the wrapped bytes. */
    public byte[] unwrap(byte[] wrappedDek) {
        if (wrappedDek.length < 1) {
            throw new CryptoException("Wrapped DEK too short: expected at least 1 header byte, got " + wrappedDek.length);
        }

        int kekVersion = wrappedDek[0] & 0xFF;
        byte[] kek = kekByVersion.get(kekVersion);
        if (kek == null) {
            throw new CryptoException("No KEK version " + kekVersion + " loaded");
        }

        byte[] ivCiphertextTag = Arrays.copyOfRange(wrappedDek, 1, wrappedDek.length);
        return AesGcmCodec.decrypt(kek, ivCiphertextTag);
    }
}
