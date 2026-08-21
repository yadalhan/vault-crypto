package com.xaan.vault.crypto;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * BCrypt one-way password hashing. Unlike the {@code envelope} package's KEK-DEK
 * encryption, this needs no external key - BCrypt generates and embeds its own salt -
 * so it has no dependency on Vault. It lives here anyway so applications can treat
 * vault-crypto as the single place password-related crypto primitives come from,
 * rather than reaching for a security library directly for this one piece.
 */
public class PasswordHasher {

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String hashedPassword) {
        return encoder.matches(rawPassword, hashedPassword);
    }
}
