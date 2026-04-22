package com.etcmc.etcauth.listener;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.auth.AuthState;
import com.etcmc.etcauth.database.Account;
import com.etcmc.etcauth.integration.FloodgateHook;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;

import java.util.Optional;
import java.util.UUID;

/**
 * Pre-login decision point. Runs on Netty thread BEFORE the player
 * actually joins the world.
 *
 * <p>Steps:
 * <ol>
 *   <li>Resolve the canonical premium UUID for the username via Mojang.</li>
 *   <li>If the connecting UUID equals the Mojang UUID -> PREMIUM path:
 *       <ul>
 *         <li>If an offline account already exists with this name,
 *             trigger the premium-claim flow (handled in JoinQuitListener
 *             once the Player object exists).</li>
 *         <li>Mark session as PREMIUM_AUTHENTICATED.</li>
 *       </ul>
 *   </li>
 *   <li>Else -> OFFLINE path:
 *       <ul>
 *         <li>If Mojang says this name IS premium (but UUID doesn't match),
 *             reject the login (impersonation attempt).</li>
 *         <li>If account exists & is locked -> reject.</li>
 *         <li>If account exists -> AWAITING_LOGIN.</li>
 *         <li>Else -> AWAITING_REGISTER.</li>
 *       </ul>
 *   </li>
 * </ol>
 */
public final class PreLoginListener implements Listener {

    private final ETCAuth plugin;
    private final AuthManager auth;
    private final MiniMessage mm = MiniMessage.miniMessage();

    public PreLoginListener(ETCAuth plugin, AuthManager auth) {
        this.plugin = plugin;
        this.auth = auth;
    }

    @EventHandler(priority = EventPriority.NORMAL)
    public void onPreLogin(AsyncPlayerPreLoginEvent ev) {
        UUID connectingUuid = ev.getUniqueId();
        String username = ev.getName();
        String ip = ev.getAddress() != null ? ev.getAddress().getHostAddress() : null;

        // 0) Bedrock player via Floodgate? They are pre-authenticated by
        // Microsoft, treat as premium with no password.
        if (FloodgateHook.isBedrock(connectingUuid) || FloodgateHook.isBedrockUsername(username)) {
            auth.registerSession(new AuthSession(
                connectingUuid, username, ip, AuthState.PREMIUM_AUTHENTICATED, true));
            return;
        }

        // Determine whether premium auto-claim is even possible. Without
        // online-mode (or a forwarding proxy / FastLogin), we cannot tell a
        // genuine premium owner apart from someone using their name, because
        // the server hands out a deterministic offline UUID for every login.
        boolean premiumEnabled = plugin.getConfig().getBoolean("premium.enabled", true);
        boolean requireOnline = plugin.getConfig().getBoolean("premium.require-online-mode-for-claim", true);
        boolean canTrustUuid  = plugin.getServer().getOnlineMode();
        boolean premiumActive = premiumEnabled && (!requireOnline || canTrustUuid);

        if (!premiumActive) {
            // Force-offline mode: every Java client (including premium owners)
            // must /register + /login. No Mojang lookup, no impersonation kick.
            Optional<Account> existingOff = auth.findAccount(username);
            AuthState initOff;
            if (existingOff.isPresent()) {
                if (existingOff.get().isLocked()) {
                    ev.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                        mm.deserialize(plugin.messages().raw("prelogin.account-locked")));
                    return;
                }
                initOff = AuthState.AWAITING_LOGIN;
            } else {
                initOff = AuthState.AWAITING_REGISTER;
            }
            auth.registerSession(new AuthSession(connectingUuid, username, ip, initOff, false));
            return;
        }

        // 1) Resolve premium UUID from Mojang
        Optional<UUID> premiumUuid;
        try {
            premiumUuid = auth.resolvePremiumUuid(username);
        } catch (Exception e) {
            plugin.getLogger().warning("Mojang lookup failed for " + username + ": " + e.getMessage());
            // Fail-open: treat as offline. We could fail-closed if desired.
            premiumUuid = Optional.empty();
        }

        Optional<Account> existing = auth.findAccount(username);
        boolean isPremium = premiumUuid.isPresent() && premiumUuid.get().equals(connectingUuid);

        // 2) Anti-impersonation: kick offline UUIDs on premium names ONLY
        // when our DB already records that name's premium owner (matches
        // PremiumHandshake policy). Until the owner has been seen / claimed,
        // the name remains freely claimable offline.
        if (premiumUuid.isPresent() && !isPremium) {
            boolean ownerKnown;
            try {
                Optional<Account> ownerRecord = plugin.database().findByUuid(premiumUuid.get());
                ownerKnown = ownerRecord.isPresent() && ownerRecord.get().isPremium();
            } catch (Exception e) {
                ownerKnown = false;
            }
            if (ownerKnown) {
                ev.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    mm.deserialize(plugin.messages().raw("prelogin.account-locked")));
                return;
            }
        }

        AuthState initial;
        if (isPremium) {
            initial = AuthState.PREMIUM_AUTHENTICATED;
        } else if (existing.isPresent()) {
            if (existing.get().isLocked()) {
                ev.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                    mm.deserialize(plugin.messages().raw("prelogin.account-locked")));
                return;
            }
            initial = AuthState.AWAITING_LOGIN;
        } else {
            initial = AuthState.AWAITING_REGISTER;
        }

        // 3) Build the session record
        AuthSession session = new AuthSession(connectingUuid, username, ip, initial, isPremium);
        auth.registerSession(session);
    }
}
