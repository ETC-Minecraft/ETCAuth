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

    public Account(UUID uuid,
                   String username,
                   String passwordHash,
                   boolean premium,
                   boolean locked,
                   String lastIp,
                   long lastLoginEpochMs,
                   long createdEpochMs,
                   byte[] inventoryBlob) {
        this.uuid = uuid;
        this.username = username;
        this.passwordHash = passwordHash;
        this.premium = premium;
        this.locked = locked;
        this.lastIp = lastIp;
        this.lastLoginEpochMs = lastLoginEpochMs;
        this.createdEpochMs = createdEpochMs;
        this.inventoryBlob = inventoryBlob;
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
}
