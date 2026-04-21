package com.etcmc.etcauth.listener;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.auth.AuthState;
import com.etcmc.etcauth.database.Account;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;

import java.util.Map;
import java.util.Optional;

public final class JoinQuitListener implements Listener {

    private final ETCAuth plugin;
    private final AuthManager auth;

    public JoinQuitListener(ETCAuth plugin, AuthManager auth) {
        this.plugin = plugin;
        this.auth = auth;
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent ev) {
        Player player = ev.getPlayer();
        AuthSession s = auth.getSession(player.getUniqueId());

        // Defensive: PreLogin may not have created a session if the event
        // was somehow skipped (Geyser, plugin reordering). Build one.
        if (s == null) {
            s = auth.registerSession(new AuthSession(
                player.getUniqueId(), player.getName(),
                player.getAddress() != null ? player.getAddress().getAddress().getHostAddress() : null,
                AuthState.AWAITING_REGISTER, false));
        }
        final AuthSession session = s;

        // PREMIUM: handle take-over of an offline account that owns this name
        if (session.getState() == AuthState.PREMIUM_AUTHENTICATED) {
            plugin.async(() -> {
                Optional<Account> existing = auth.findAccount(player.getName());
                if (existing.isPresent() && !existing.get().isPremium()) {
                    auth.claimForPremium(player, existing.get());
                } else if (existing.isEmpty()) {
                    // First-time premium join: store a stub premium account
                    try {
                        long now = System.currentTimeMillis();
                        plugin.database().insert(new Account(
                            player.getUniqueId(), player.getName(), null,
                            true, false,
                            session.getIp(), now, now, null));
                    } catch (Exception e) {
                        plugin.getLogger().warning("Could not create premium stub: " + e.getMessage());
                    }
                }
            });
            plugin.messages().send(player, "join.welcome-premium",
                Map.of("player", player.getName()));
            applyIntegrations(player, session);
            return;
        }

        // OFFLINE: try IP auto-login first
        if (session.getState() == AuthState.AWAITING_LOGIN
                && auth.tryAutoLoginByIp(player)) {
            plugin.messages().send(player, "join.auto-login-ip",
                Map.of("player", player.getName()));
            applyIntegrations(player, session);
            return;
        }

        // Freeze location and start login timeout
        session.setFrozenLocation(player.getLocation());

        if (session.getState() == AuthState.AWAITING_REGISTER) {
            plugin.messages().send(player, "join.welcome-offline-register");
        } else {
            int timeout = plugin.getConfig().getInt("auth.login-timeout-seconds", 60);
            plugin.messages().send(player, "join.welcome-offline-login",
                Map.of("time", String.valueOf(timeout),
                       "player", player.getName()));
        }

        scheduleLoginTimeout(player, session);
    }

    /**
     * Push the player's auth state to LuckPerms (group sync) and to
     * ETCCore (variable bridge) so other systems can react.
     */
    private void applyIntegrations(Player player, AuthSession session) {
        plugin.async(() -> {
            try {
                if (session.isPremium()) plugin.luckPerms().applyPremium(player);
                else                     plugin.luckPerms().applyOffline(player);
            } catch (Throwable ignored) { }
            try {
                plugin.etcCoreBridge().publish(player, session);
            } catch (Throwable ignored) { }
        });
    }

    private void scheduleLoginTimeout(Player player, AuthSession session) {
        long timeoutTicks = plugin.getConfig().getLong("auth.login-timeout-seconds", 60) * 20L;
        player.getScheduler().runDelayed(plugin, t -> {
            AuthSession s = auth.getSession(player.getUniqueId());
            if (s == null || s.isAuthenticated()) return;
            if (!player.isOnline()) return;
            player.kick(plugin.messages().kickMessage("login.timeout-kick", null));
        }, null, timeoutTicks);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent ev) {
        Player player = ev.getPlayer();
        AuthSession s = auth.getSession(player.getUniqueId());
        if (s != null && s.getState() == AuthState.OFFLINE_AUTHENTICATED) {
            // Persist inventory snapshot for potential premium claim later
            plugin.async(() -> auth.persistInventorySnapshot(player));
        }
        auth.removeSession(player.getUniqueId());
    }
}
