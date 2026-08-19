package com.xaan.vault.crypto.envelope;

/**
 * A single KEK-wrapped DEK version for a service domain, as stored in Vault.
 */
public record WrappedDek(String domain, int version, byte[] wrappedBytes) {
}
