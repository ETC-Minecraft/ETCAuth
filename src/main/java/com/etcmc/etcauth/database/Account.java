package com.etcmc.etcauth.database;

import java.util.UUID;

/**
 * Account record for a registered user (premium or offline).
 *
 * <p>For premium accounts, {@link #passwordHash} is {@code null} — they
 * authenticate via Mojang's session servers.
 */
public final class Account {

    private final UUID uuid;
    private final String username;
    private final String passwordHash;       // null for premium
    private final boolean premium;
    private final boolean locked;            // claimed by premium owner; offline data frozen
    private final String lastIp;
    private final long lastLoginEpochMs;
    private final long createdEpochMs;
    private final byte[] inventoryBlob;      // serialized inventory from prior offline owner (claim payload)
    private final String totpSecret;         // base32 TOTP secret, or null if 2FA disabled
    private final String skinValue;          // Mojang textures property "value"
    private final String skinSignature;      // Mojang textures property "signature"
    private final String email;              // optional, for recovery
    private final String resetToken;         // null when no recovery in progress
    private final long resetTokenExpiresMs;  // 0 when no recovery in progress

    public Account(UUID uuid,
                   String username,
                   String passwordHash,
                   boolean premium,
                   boolean locked,
                   String lastIp,
                   long lastLoginEpochMs,
                   long createdEpochMs,
                   byte[] inventoryBlob,
                   String totpSecret,
                   String skinValue,
                   String skinSignature,
                   String email,
                   String resetToken,
                   long resetTokenExpiresMs) {
        this.uuid = uuid;
        this.username = username;
        this.passwordHash = passwordHash;
        this.premium = premium;
        this.locked = locked;
        this.lastIp = lastIp;
        this.lastLoginEpochMs = lastLoginEpochMs;
        this.createdEpochMs = createdEpochMs;
        this.inventoryBlob = inventoryBlob;
        this.totpSecret = totpSecret;
        this.skinValue = skinValue;
        this.skinSignature = skinSignature;
        this.email = email;
        this.resetToken = resetToken;
        this.resetTokenExpiresMs = resetTokenExpiresMs;
    }

    /** Convenience constructor used by Phase 2 callers (no email/recovery). */
    public Account(UUID uuid,
                   String username,
                   String passwordHash,
                   boolean premium,
                   boolean locked,
                   String lastIp,
                   long lastLoginEpochMs,
                   long createdEpochMs,
                   byte[] inventoryBlob,
                   String totpSecret,
                   String skinValue,
                   String skinSignature) {
        this(uuid, username, passwordHash, premium, locked, lastIp,
             lastLoginEpochMs, createdEpochMs, inventoryBlob,
             totpSecret, skinValue, skinSignature,
             null, null, 0L);
    }

    /** Convenience constructor for callers that don't touch TOTP/skin. */
    public Account(UUID uuid,
                   String username,
                   String passwordHash,
                   boolean premium,
                   boolean locked,
                   String lastIp,
                   long lastLoginEpochMs,
                   long createdEpochMs,
                   byte[] inventoryBlob) {
        this(uuid, username, passwordHash, premium, locked, lastIp,
             lastLoginEpochMs, createdEpochMs, inventoryBlob,
             null, null, null,
             null, null, 0L);
    }

    public UUID getUuid()              { return uuid; }
    public String getUsername()        { return username; }
    public String getPasswordHash()    { return passwordHash; }
    public boolean isPremium()         { return premium; }
    public boolean isLocked()          { return locked; }
    public String getLastIp()          { return lastIp; }
    public long getLastLoginEpochMs()  { return lastLoginEpochMs; }
    public long getCreatedEpochMs()    { return createdEpochMs; }
    public byte[] getInventoryBlob()   { return inventoryBlob; }
    public String getTotpSecret()      { return totpSecret; }
    public String getSkinValue()       { return skinValue; }
    public String getSkinSignature()   { return skinSignature; }
    public String getEmail()                 { return email; }
    public String getResetToken()            { return resetToken; }
    public long   getResetTokenExpiresMs()   { return resetTokenExpiresMs; }

    /** Return a copy with the given TOTP secret applied. */
    public Account withTotpSecret(String secret) {
        return new Account(uuid, username, passwordHash, premium, locked,
            lastIp, lastLoginEpochMs, createdEpochMs, inventoryBlob,
            secret, skinValue, skinSignature, email, resetToken, resetTokenExpiresMs);
    }

    /** Return a copy with the given skin properties applied. */
    public Account withSkin(String value, String signature) {
        return new Account(uuid, username, passwordHash, premium, locked,
            lastIp, lastLoginEpochMs, createdEpochMs, inventoryBlob,
            totpSecret, value, signature, email, resetToken, resetTokenExpiresMs);
    }

    public Account withEmail(String newEmail) {
        return new Account(uuid, username, passwordHash, premium, locked,
            lastIp, lastLoginEpochMs, createdEpochMs, inventoryBlob,
            totpSecret, skinValue, skinSignature, newEmail, resetToken, resetTokenExpiresMs);
    }

    public Account withResetToken(String token, long expiresMs) {
        return new Account(uuid, username, passwordHash, premium, locked,
            lastIp, lastLoginEpochMs, createdEpochMs, inventoryBlob,
            totpSecret, skinValue, skinSignature, email, token, expiresMs);
    }

    public Account withPasswordHash(String newHash) {
        return new Account(uuid, username, newHash, premium, locked,
            lastIp, lastLoginEpochMs, createdEpochMs, inventoryBlob,
            totpSecret, skinValue, skinSignature, email, resetToken, resetTokenExpiresMs);
    }
}
