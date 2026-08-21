package com.xaan.vault.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHasherTest {

    private final PasswordHasher passwordHasher = new PasswordHasher();

    @Test
    void hashedPasswordIsNotThePlaintext() {
        String hashed = passwordHasher.hash("s3cret!");

        assertNotEquals("s3cret!", hashed);
    }

    @Test
    void matchesReturnsTrueForTheCorrectPassword() {
        String hashed = passwordHasher.hash("s3cret!");

        assertTrue(passwordHasher.matches("s3cret!", hashed));
    }

    @Test
    void matchesReturnsFalseForTheWrongPassword() {
        String hashed = passwordHasher.hash("s3cret!");

        assertFalse(passwordHasher.matches("wrong-password", hashed));
    }
}
