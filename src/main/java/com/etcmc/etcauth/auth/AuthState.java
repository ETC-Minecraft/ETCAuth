package com.etcmc.etcauth.auth;

/**
 * Authentication state for a connected player.
 */
public enum AuthState {
    /** Premium player, verified via Mojang. No password required. */
    PREMIUM_AUTHENTICATED,

    /** Offline player, registered, has provided correct password. */
    OFFLINE_AUTHENTICATED,

    /** Offline player, registered, awaiting /login. */
    AWAITING_LOGIN,

    /** Offline player, NOT registered, awaiting /register. */
    AWAITING_REGISTER
}
