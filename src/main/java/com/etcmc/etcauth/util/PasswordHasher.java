package com.etcmc.etcauth.util;

import at.favre.lib.crypto.bcrypt.BCrypt;

/**
 * BCrypt-backed password hashing utility with optional global pepper.
 *
 * <p>The pepper is concatenated to the plaintext before hashing. It is
 * never stored in the database — only in {@code config.yml} (or, ideally,
 * in an environment variable referenced from config). If an attacker
 * exfiltrates {@code accounts.db} but not the pepper, the hashes are
 * effectively un-crackable even by GPU farms.
 *
 * <p>If you change the pepper after accounts exist, every existing
 * password becomes invalid. Treat it like a master key.
 */
public final class PasswordHasher {

    private final int cost;
    private final String pepper;

    public PasswordHasher(int cost, String pepper) {
        this.cost = Math.max(4, Math.min(31, cost));
        this.pepper = pepper == null ? "" : pepper;
    }

    public String hash(String plaintext) {
        return BCrypt.withDefaults().hashToString(cost, applyPepper(plaintext).toCharArray());
    }

    public boolean verify(String plaintext, String hash) {
        if (hash == null || hash.isEmpty()) return false;
        BCrypt.Result r = BCrypt.verifyer().verify(applyPepper(plaintext).toCharArray(), hash);
        return r.verified;
    }

    private String applyPepper(String plaintext) {
        return pepper.isEmpty() ? plaintext : plaintext + pepper;
    }
}
