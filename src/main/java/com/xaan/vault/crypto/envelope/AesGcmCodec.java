package com.xaan.vault.crypto.envelope;

import com.xaan.vault.crypto.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * Low-level AES-256-GCM byte codec shared by KEK wrap/unwrap and DEK-based
 * envelope encryption. Output format: IV(12 bytes) + ciphertext + GCM tag(16 bytes).
 */
final class AesGcmCodec {

    static final String ALGORITHM = "AES/GCM/NoPadding";
    static final int TAG_LENGTH_BITS = 128;
    static final int IV_LENGTH_BYTES = 12;

    private AesGcmCodec() {
    }

    static byte[] encrypt(byte[] key, byte[] plaintext) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance(ALGORITHM);

            byte[] iv = new byte[IV_LENGTH_BYTES];
            new SecureRandom().nextBytes(iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));

            byte[] ciphertext = cipher.doFinal(plaintext);

            ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
            buffer.put(iv);
            buffer.put(ciphertext);
            return buffer.array();
        } catch (Exception e) {
            throw new CryptoException("Error encrypting data", e);
        }
    }

    static byte[] decrypt(byte[] key, byte[] ivCiphertextTag) {
        try {
            int minLength = IV_LENGTH_BYTES + TAG_LENGTH_BITS / 8;
            if (ivCiphertextTag.length < minLength) {
                throw new CryptoException("Encrypted data too short: expected at least " +
                        minLength + " bytes, got " + ivCiphertextTag.length);
            }

            ByteBuffer buffer = ByteBuffer.wrap(ivCiphertextTag);
            byte[] iv = new byte[IV_LENGTH_BYTES];
            buffer.get(iv);
            byte[] ciphertext = new byte[buffer.remaining()];
            buffer.get(ciphertext);

            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));

            return cipher.doFinal(ciphertext);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Error decrypting data", e);
        }
    }
}
