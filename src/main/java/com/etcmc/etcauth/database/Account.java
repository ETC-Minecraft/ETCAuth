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
             null, null, null);
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

    /** Return a copy with the given TOTP secret applied. */
    public Account withTotpSecret(String secret) {
        return new Account(uuid, username, passwordHash, premium, locked,
            lastIp, lastLoginEpochMs, createdEpochMs, inventoryBlob,
            secret, skinValue, skinSignature);
    }

    /** Return a copy with the given skin properties applied. */
    public Account withSkin(String value, String signature) {
        return new Account(uuid, username, passwordHash, premium, locked,
            lastIp, lastLoginEpochMs, createdEpochMs, inventoryBlob,
            totpSecret, value, signature);
    }
}
