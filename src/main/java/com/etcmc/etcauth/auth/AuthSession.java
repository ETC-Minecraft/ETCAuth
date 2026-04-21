package com.etcmc.etcauth.auth;

import org.bukkit.Location;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Per-player runtime authentication session.
 *
 * <p>Created in {@code AsyncPlayerPreLoginEvent} (premium decision is
 * known at that point) and disposed on {@code PlayerQuitEvent}.
 */
public final class AuthSession {

    private final UUID uuid;
    private final String username;
    private final String ip;
    private volatile AuthState state;
    private final long joinTimeMs;
    private final AtomicInteger failedAttempts = new AtomicInteger();
    private volatile long failedLockUntilMs;
    private volatile Location frozenLocation;   // for movement restriction
    /** When the premium UUID for this username has been verified via Mojang. */
    private final boolean premium;

    public AuthSession(UUID uuid, String username, String ip,
                       AuthState initialState, boolean premium) {
        this.uuid = uuid;
        this.username = username;
        this.ip = ip;
        this.state = initialState;
        this.premium = premium;
        this.joinTimeMs = System.currentTimeMillis();
    }

    public UUID getUuid()                 { return uuid; }
    public String getUsername()           { return username; }
    public String getIp()                 { return ip; }
    public AuthState getState()           { return state; }
    public void setState(AuthState s)     { this.state = s; }
    public long getJoinTimeMs()           { return joinTimeMs; }
    public boolean isPremium()            { return premium; }

    public boolean isAuthenticated() {
        return state == AuthState.PREMIUM_AUTHENTICATED
            || state == AuthState.OFFLINE_AUTHENTICATED;
    }

    public int incrementFailed()          { return failedAttempts.incrementAndGet(); }
    public int getFailedAttempts()        { return failedAttempts.get(); }
    public void resetFailedAttempts()     { failedAttempts.set(0); }

    public long getFailedLockUntilMs()    { return failedLockUntilMs; }
    public void setFailedLockUntilMs(long ms) { this.failedLockUntilMs = ms; }

    public Location getFrozenLocation()         { return frozenLocation; }
    public void setFrozenLocation(Location loc) { this.frozenLocation = loc; }

    /** Original location captured BEFORE teleport to the limbo world. */
    private volatile Location preLimboLocation;
    public Location getPreLimboLocation()         { return preLimboLocation; }
    public void setPreLimboLocation(Location loc) { this.preLimboLocation = loc; }

    /** True when password verified but a TOTP code is still required. */
    private volatile boolean awaiting2fa;
    public boolean isAwaiting2fa()           { return awaiting2fa; }
    public void setAwaiting2fa(boolean v)    { this.awaiting2fa = v; }
}
