package com.xaan.vault.crypto.envelope;

import com.xaan.vault.crypto.CryptoException;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KekRotationTest {

    @Test
    void wrapEmbedsCurrentKekVersion_unwrapDispatchesByIt() {
        Map<Integer, byte[]> keks = new HashMap<>();
        keks.put(1, randomBytes(32));
        keks.put(2, randomBytes(32));
        KekService ring = new KekService(keks, 2);

        byte[] plainDek = randomBytes(32);
        byte[] wrapped = ring.wrap(plainDek);

        assertEquals(2, wrapped[0] & 0xFF);
        assertArrayEquals(plainDek, ring.unwrap(wrapped));
    }

    @Test
    void oldKekVersionStillUnwrapsAfterNewVersionBecomesCurrent() {
        byte[] kekV1 = randomBytes(32);
        KekService ringV1Only = new KekService(Map.of(1, kekV1), 1);

        byte[] plainDek = randomBytes(32);
        byte[] wrappedUnderV1 = ringV1Only.wrap(plainDek);

        // Simulate a rotation: rebuild the ring with both versions loaded, v2 now current.
        Map<Integer, byte[]> both = new HashMap<>();
        both.put(1, kekV1);
        both.put(2, randomBytes(32));
        KekService ringBoth = new KekService(both, 2);

        assertArrayEquals(plainDek, ringBoth.unwrap(wrappedUnderV1));
    }

    @Test
    void unwrapFailsWhenItsKekVersionIsNotLoaded() {
        KekService ringV2Only = new KekService(Map.of(2, randomBytes(32)), 2);
        byte[] wrappedUnderUnloadedV1 = new byte[]{1, 0, 0, 0};

        assertThrows(CryptoException.class, () -> ringV2Only.unwrap(wrappedUnderUnloadedV1));
    }

    @Test
    void rotationSupportIssuesNewVersionAndRewrapsDomainDeksWithoutChangingDekVersion() {
        InMemoryKekProvider kekProvider = new InMemoryKekProvider();
        kekProvider.store(1, randomBytes(32), 1);
        KekService kekV1Only = KekService.load(kekProvider);

        InMemoryDekProvider dekProvider = new InMemoryDekProvider();
        byte[] plainDek = randomBytes(32);
        byte[] wrappedUnderV1 = kekV1Only.wrap(plainDek);
        dekProvider.store("board", new WrappedDek("board", 1, wrappedUnderV1), 1);

        KekRotationSupport rotation = new KekRotationSupport(kekProvider);
        int newKekVersion = rotation.issueNewKekVersion();
        assertEquals(2, newKekVersion);

        // A fresh ring picks up both KEK versions (old, to unwrap; new, to re-wrap with).
        KekService kekBoth = KekService.load(kekProvider);
        rotation.rewrapDomainDeks(kekBoth, dekProvider, "board");

        WrappedDek rewrapped = dekProvider.loadAll("board").get(0);
        assertEquals(2, rewrapped.wrappedBytes()[0] & 0xFF, "DEK should now be wrapped under the new KEK version");
        assertArrayEquals(plainDek, kekBoth.unwrap(rewrapped.wrappedBytes()));
        assertEquals(1, dekProvider.loadCurrentVersion("board"), "rewrapping must not change the DEK version pointer");
    }

    @Test
    void retiringTheCurrentKekVersionIsRejected() {
        InMemoryKekProvider kekProvider = new InMemoryKekProvider();
        kekProvider.store(1, randomBytes(32), 1);

        assertThrows(IllegalArgumentException.class, () -> kekProvider.retire(1));
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static final class InMemoryKekProvider implements KekProvider {
        private final Map<Integer, byte[]> keks = new HashMap<>();
        private int currentVersion;

        @Override
        public Map<Integer, byte[]> loadAll() {
            return Map.copyOf(keks);
        }

        @Override
        public int loadCurrentVersion() {
            return currentVersion;
        }

        @Override
        public void store(int newVersion, byte[] newKekBytes, int newCurrentVersion) {
            keks.put(newVersion, newKekBytes);
            currentVersion = newCurrentVersion;
        }

        @Override
        public void retire(int version) {
            if (version == currentVersion) {
                throw new IllegalArgumentException("Refusing to retire the current KEK version " + version);
            }
            keks.remove(version);
        }
    }

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
