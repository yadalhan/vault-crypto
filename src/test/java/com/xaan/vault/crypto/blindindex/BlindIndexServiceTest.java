package com.xaan.vault.crypto.blindindex;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class BlindIndexServiceTest {

    private BlindIndexService phoneIndex;

    @BeforeEach
    void setUp() {
        InMemoryBlindIndexKeyProvider provider = new InMemoryBlindIndexKeyProvider();
        provider.storeKey("user-phone", randomBytes(32));
        provider.storeKey("user-rrn", randomBytes(32));
        phoneIndex = BlindIndexService.forIndex("user-phone", provider);
    }

    @Test
    void sameInputAlwaysProducesTheSameIndex() {
        assertEquals(phoneIndex.compute("01012345678"), phoneIndex.compute("01012345678"));
    }

    @Test
    void differentInputsProduceDifferentIndexes() {
        assertNotEquals(phoneIndex.compute("01012345678"), phoneIndex.compute("01087654321"));
    }

    @Test
    void differentIndexNamesUseIndependentKeysEvenForTheSamePlaintext() {
        InMemoryBlindIndexKeyProvider provider = new InMemoryBlindIndexKeyProvider();
        provider.storeKey("user-phone", randomBytes(32));
        provider.storeKey("user-rrn", randomBytes(32));
        BlindIndexService rrnIndex = BlindIndexService.forIndex("user-rrn", provider);
        BlindIndexService samePhoneIndex = BlindIndexService.forIndex("user-phone", provider);

        assertNotEquals(rrnIndex.compute("9001011234567"), samePhoneIndex.compute("9001011234567"));
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static final class InMemoryBlindIndexKeyProvider implements BlindIndexKeyProvider {
        private final Map<String, byte[]> keys = new HashMap<>();

        @Override
        public byte[] loadKey(String indexName) {
            return keys.get(indexName);
        }

        @Override
        public void storeKey(String indexName, byte[] key) {
            keys.put(indexName, key);
        }
    }
}
