package com.xaan.vault.crypto.envelope;

import com.xaan.vault.crypto.CryptoException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * Domain-scoped envelope encryption: encrypts/decrypts with the DEK cached in a
 * {@link DomainKeyRing}, never the KEK. One instance per service domain (e.g. "board",
 * "user-pii"), typically held as a long-lived Spring singleton so the DEK unwrap
 * (KEK round trip) happens once at startup rather than per call.
 *
 * <p>Ciphertext format: {@code Base64URL( domainCode(1B) | keyVersion(1B) | IV(12B) | ciphertext+tag )}.
 * The version byte lets old data keep decrypting after a DEK rotation; the domain
 * byte stops a ciphertext from one domain being decrypted with another domain's DEK.
 */
public class EnvelopeCryptoService {

    private final byte domainCode;
    private final DomainKeyRing keyRing;

    private EnvelopeCryptoService(byte domainCode, DomainKeyRing keyRing) {
        this.domainCode = domainCode;
        this.keyRing = keyRing;
    }

    public static EnvelopeCryptoService forDomain(byte domainCode, String domain, KekService kek, DekProvider dekProvider) {
        return new EnvelopeCryptoService(domainCode, DomainKeyRing.load(domain, kek, dekProvider));
    }

    /** The DEK version encrypt() currently uses - i.e. what a post-rotation reencryption batch should converge rows toward. */
    public int currentVersion() {
        return keyRing.currentVersion();
    }

    /**
     * Reads the keyVersion recorded in a ciphertext's header without decrypting it -
     * lets a reencryption batch skip rows already on {@link #currentVersion()} instead
     * of paying for a decrypt+encrypt round trip on every row.
     */
    public int versionOf(String encryptedText) {
        byte[] combined = Base64.getUrlDecoder().decode(encryptedText);
        if (combined.length < 2) {
            throw new CryptoException("Envelope too short: expected at least 2 header bytes, got " + combined.length);
        }
        return combined[1] & 0xFF;
    }

    public String encrypt(String plainText) {
        var key = keyRing.currentKey();
        byte[] ivCiphertextTag = AesGcmCodec.encrypt(key.getEncoded(), plainText.getBytes(StandardCharsets.UTF_8));

        ByteBuffer buffer = ByteBuffer.allocate(2 + ivCiphertextTag.length);
        buffer.put(domainCode);
        buffer.put((byte) keyRing.currentVersion());
        buffer.put(ivCiphertextTag);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer.array());
    }

    public String decrypt(String encryptedText) {
        byte[] combined = Base64.getUrlDecoder().decode(encryptedText);
        if (combined.length < 2) {
            throw new CryptoException("Envelope too short: expected at least 2 header bytes, got " + combined.length);
        }

        byte messageDomainCode = combined[0];
        int version = combined[1] & 0xFF;
        if (messageDomainCode != domainCode) {
            throw new CryptoException("Envelope domain mismatch: expected " + domainCode + " but got " + messageDomainCode);
        }

        byte[] ivCiphertextTag = Arrays.copyOfRange(combined, 2, combined.length);
        var key = keyRing.keyFor(version);
        byte[] plain = AesGcmCodec.decrypt(key.getEncoded(), ivCiphertextTag);
        return new String(plain, StandardCharsets.UTF_8);
    }

    /** Constant-time comparison of plaintext input against a stored envelope ciphertext. */
    public boolean validate(String input, String storedEncrypted) {
        try {
            String decrypted = decrypt(storedEncrypted);
            return MessageDigest.isEqual(
                    decrypted.getBytes(StandardCharsets.UTF_8),
                    input.getBytes(StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            byte[] dummy = new byte[16];
            MessageDigest.isEqual(dummy, input.getBytes(StandardCharsets.UTF_8));
            return false;
        }
    }
}
