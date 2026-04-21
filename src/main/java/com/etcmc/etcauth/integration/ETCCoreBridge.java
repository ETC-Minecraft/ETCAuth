package com.etcmc.etcauth.integration;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.database.Account;
import org.bukkit.entity.Player;

import java.util.Optional;
import java.util.UUID;

/**
 * Bridge to ETCCore's {@code PlayerDataManager}.
 *
 * <p>Exposes the player's auth state as a set of variables that
 * ETCCore's custom command/menu system can read via
 * {@code {var:etcauth_<key>}}:
 *
 * <ul>
 *   <li>{@code etcauth_premium}    — "true" / "false"</li>
 *   <li>{@code etcauth_state}      — current AuthState name</li>
 *   <li>{@code etcauth_lastlogin}  — epoch ms of previous login</li>
 *   <li>{@code etcauth_lastip}     — last known IP</li>
 *   <li>{@code etcauth_created}    — account creation epoch ms</li>
 * </ul>
 *
 * <p>If ETCCore is not installed, every method silently no-ops.
 */
public final class ETCCoreBridge {

    private final ETCAuth plugin;
    private Object playerDataManager;       // erased to avoid hard-link
    private boolean available;

    public ETCCoreBridge(ETCAuth plugin) {
        this.plugin = plugin;
        try {
            Class<?> cls = Class.forName("com.etcmc.etccore.ETCCore");
            Object core = cls.getMethod("getInstance").invoke(null);
            if (core != null) {
                playerDataManager = cls.getMethod("getPlayerDataManager").invoke(core);
                available = playerDataManager != null;
            }
        } catch (Throwable t) {
            available = false;
        }
        if (available) {
            plugin.getLogger().info("ETCCore bridge active — exposing variables.");
        }
    }

    public boolean isAvailable() { return available; }

    public void publish(Player player, AuthSession session) {
        if (!available) return;
        UUID uuid = player.getUniqueId();
        Optional<Account> opt = plugin.authManager().findAccount(player.getName());
        Account a = opt.orElse(null);

        setBool(uuid, "etcauth_premium", session.isPremium());
        setString(uuid, "etcauth_state", session.getState().name());
        if (a != null) {
            setString(uuid, "etcauth_lastlogin", String.valueOf(a.getLastLoginEpochMs()));
            setString(uuid, "etcauth_lastip",    a.getLastIp() == null ? "" : a.getLastIp());
            setString(uuid, "etcauth_created",   String.valueOf(a.getCreatedEpochMs()));
        }
    }

    private void setBool(UUID uuid, String key, boolean value) {
        try {
            playerDataManager.getClass()
                .getMethod("setBool", UUID.class, String.class, boolean.class)
                .invoke(playerDataManager, uuid, key, value);
        } catch (Throwable ignored) { }
    }

    private void setString(UUID uuid, String key, String value) {
        try {
            playerDataManager.getClass()
                .getMethod("set", UUID.class, String.class, String.class)
                .invoke(playerDataManager, uuid, key, value);
        } catch (Throwable ignored) { }
    }
}
