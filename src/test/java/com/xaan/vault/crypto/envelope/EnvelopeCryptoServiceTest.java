package com.xaan.vault.crypto.envelope;

import com.xaan.vault.crypto.CryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnvelopeCryptoServiceTest {

    private static final byte BOARD_DOMAIN_CODE = 1;
    private static final byte USER_PII_DOMAIN_CODE = 2;

    private KekService kek;
    private InMemoryDekProvider dekProvider;

    @BeforeEach
    void setUp() {
        kek = new KekService(randomBytes(32));
        dekProvider = new InMemoryDekProvider();
        seedDek("board", 1);
        seedDek("user-pii", 1);
    }

    @Test
    void encryptThenDecryptRoundTrips() {
        EnvelopeCryptoService board = EnvelopeCryptoService.forDomain(BOARD_DOMAIN_CODE, "board", kek, dekProvider);

        String encrypted = board.encrypt("s3cret-post-password");
        assertEquals("s3cret-post-password", board.decrypt(encrypted));
    }

    @Test
    void validateSucceedsForCorrectInputAndFailsForWrongInput() {
        EnvelopeCryptoService board = EnvelopeCryptoService.forDomain(BOARD_DOMAIN_CODE, "board", kek, dekProvider);
        String encrypted = board.encrypt("correct-password");

        assertTrue(board.validate("correct-password", encrypted));
        assertFalse(board.validate("wrong-password", encrypted));
    }

    @Test
    void domainsAreIsolated_cannotDecryptAcrossDomains() {
        EnvelopeCryptoService board = EnvelopeCryptoService.forDomain(BOARD_DOMAIN_CODE, "board", kek, dekProvider);
        EnvelopeCryptoService userPii = EnvelopeCryptoService.forDomain(USER_PII_DOMAIN_CODE, "user-pii", kek, dekProvider);

        String boardCiphertext = board.encrypt("board-secret");

        assertThrows(CryptoException.class, () -> userPii.decrypt(boardCiphertext));
    }

    @Test
    void oldKeyVersionsStayDecryptableAfterRotation() {
        EnvelopeCryptoService boardV1 = EnvelopeCryptoService.forDomain(BOARD_DOMAIN_CODE, "board", kek, dekProvider);
        String encryptedUnderV1 = boardV1.encrypt("pre-rotation-value");

        // Rotate: add a v2 DEK and make it current, keep v1 around.
        DekRotationSupport rotation = new DekRotationSupport(kek, dekProvider);
        int newVersion = rotation.rotate("board");
        assertEquals(2, newVersion);

        // A fresh service reloads the ring and sees both versions.
        EnvelopeCryptoService boardAfterRotation = EnvelopeCryptoService.forDomain(BOARD_DOMAIN_CODE, "board", kek, dekProvider);

        // Old ciphertext (v1) still decrypts...
        assertEquals("pre-rotation-value", boardAfterRotation.decrypt(encryptedUnderV1));

        // ...and new encryptions use v2.
        String encryptedUnderV2 = boardAfterRotation.encrypt("post-rotation-value");
        assertEquals("post-rotation-value", boardAfterRotation.decrypt(encryptedUnderV2));
        assertFalse(encryptedUnderV1.equals(encryptedUnderV2));
    }

    private void seedDek(String domain, int version) {
        byte[] plaintextDek = randomBytes(32);
        byte[] wrapped = kek.wrap(plaintextDek);
        dekProvider.store(domain, new WrappedDek(domain, version, wrapped), version);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    /** Minimal in-memory stand-in for {@link VaultDekProvider}, used to avoid a live Vault in tests. */
    private static final class InMemoryDekProvider implements DekProvider {
        private final Map<String, Map<Integer, WrappedDek>> versionsByDomain = new HashMap<>();
        private final Map<String, Integer> currentVersionByDomain = new HashMap<>();

        @Override
        public List<WrappedDek> loadAll(String domain) {
            return new ArrayList<>(versionsByDomain.getOrDefault(domain, Map.of()).values());
        }

        @Override
        public int loadCurrentVersion(String domain) {
            return currentVersionByDomain.get(domain);
        }

        @Override
        public void store(String domain, WrappedDek newVersion, int newCurrentVersion) {
            versionsByDomain.computeIfAbsent(domain, d -> new HashMap<>()).put(newVersion.version(), newVersion);
            currentVersionByDomain.put(domain, newCurrentVersion);
        }

        @Override
        public void retire(String domain, int version) {
            versionsByDomain.getOrDefault(domain, Map.of()).remove(version);
        }
    }
}
