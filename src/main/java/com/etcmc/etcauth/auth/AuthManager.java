package com.etcmc.etcauth.auth;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.database.Account;
import com.etcmc.etcauth.database.AuditLog;
import com.etcmc.etcauth.database.Database;
import com.etcmc.etcauth.util.InventorySerializer;
import com.etcmc.etcauth.util.PasswordHasher;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.sql.SQLException;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Central authentication coordinator.
 *
 * <p>Owns the in-memory session table and delegates persistence to
 * {@link Database}. All public mutators are safe to call from any
 * thread, but DB-touching helpers should be invoked off-main via
 * {@link ETCAuth#async(Runnable)}.
 */
public final class AuthManager {

    private final ETCAuth plugin;
    private final Database db;
    private final PremiumChecker premiumChecker;
    private final PasswordHasher hasher;

    private final ConcurrentHashMap<UUID, AuthSession> sessions = new ConcurrentHashMap<>();

    /** username (lower) -> last successful login (uuid + ip + timestamp) for IP auto-login. */
    private final ConcurrentHashMap<String, IpSession> ipSessions = new ConcurrentHashMap<>();

    public AuthManager(ETCAuth plugin, Database db, PremiumChecker premiumChecker, PasswordHasher hasher) {
        this.plugin = plugin;
        this.db = db;
        this.premiumChecker = premiumChecker;
        this.hasher = hasher;
    }

    private void audit(String username, String event, String ip, String detail) {
        AuditLog log = plugin.audit();
        if (log != null) log.log(username, event, ip, detail);
    }

    private String ipOf(Player p) {
        return p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : null;
    }

    // -------------------------------------------------------------------
    // Session table
    // -------------------------------------------------------------------

    public AuthSession registerSession(AuthSession s) {
        sessions.put(s.getUuid(), s);
        return s;
    }

    public AuthSession getSession(UUID uuid) {
        return sessions.get(uuid);
    }

    public AuthSession getSession(Player p) {
        return sessions.get(p.getUniqueId());
    }

    public void removeSession(UUID uuid) {
        sessions.remove(uuid);
    }

    public boolean isAuthenticated(Player p) {
        AuthSession s = sessions.get(p.getUniqueId());
        return s != null && s.isAuthenticated();
    }

    // -------------------------------------------------------------------
    // Premium resolution (called from AsyncPlayerPreLoginEvent)
    // -------------------------------------------------------------------

    /** @return Mojang's canonical UUID for this name, or empty if not premium. */
    public Optional<UUID> resolvePremiumUuid(String username) throws Exception {
        if (!plugin.getConfig().getBoolean("premium.enabled", true)) return Optional.empty();
        return premiumChecker.resolve(username);
    }

    public PremiumChecker getPremiumChecker() {
        return premiumChecker;
    }

    // -------------------------------------------------------------------
    // Account lookup (DB)
    // -------------------------------------------------------------------

    public Optional<Account> findAccount(String username) {
        try {
            return db.findByUsername(username);
        } catch (SQLException e) {
            plugin.getLogger().severe("DB lookup failed for '" + username + "': " + e.getMessage());
            return Optional.empty();
        }
    }

    // -------------------------------------------------------------------
    // Registration / login flows
    // -------------------------------------------------------------------

    /**
     * Register a new offline account for {@code player}.
     * Caller must verify password rules first.
     */
    public boolean register(Player player, String password) {
        AuthSession session = getSession(player);
        if (session == null) return false;
        if (session.isPremium()) return false;

        try {
            if (db.findByUsername(player.getName()).isPresent()) return false;

            String hash = hasher.hash(password);
            long now = System.currentTimeMillis();
            Account acc = new Account(
                player.getUniqueId(),
                player.getName(),
                hash,
                false,                      // not premium
                false,                      // not locked
                player.getAddress() != null ? player.getAddress().getAddress().getHostAddress() : null,
                now,
                now,
                null);
            db.insert(acc);

            session.setState(AuthState.OFFLINE_AUTHENTICATED);
            recordIpSession(player);
            audit(player.getName(), "REGISTER", ipOf(player), null);
            return true;
        } catch (SQLException e) {
            plugin.getLogger().severe("Registration failed for " + player.getName() + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * Verify the given password and mark the session as authenticated.
     * <p>If the account has TOTP enabled, the session is moved into the
     * {@code awaiting2fa=true} state instead of being fully
     * authenticated, and the caller must wait for {@link #complete2faLogin}.
     * @return outcome of the login attempt.
     */
    public LoginResult login(Player player, String password) {
        AuthSession session = getSession(player);
        if (session == null || session.isPremium()) return LoginResult.FAILED;

        Optional<Account> opt = findAccount(player.getName());
        if (opt.isEmpty()) return LoginResult.FAILED;

        Account acc = opt.get();
        if (acc.isLocked()) return LoginResult.FAILED;
        if (!hasher.verify(password, acc.getPasswordHash())) return LoginResult.FAILED;

        // 2FA gate
        if (acc.getTotpSecret() != null) {
            session.setAwaiting2fa(true);
            return LoginResult.NEEDS_2FA;
        }

        finalizeLogin(player, session, acc);
        return LoginResult.OK;
    }

    /** Called by TwoFACommand once the TOTP code matches. */
    public void complete2faLogin(Player player, AuthSession session) {
        Optional<Account> opt = findAccount(player.getName());
        if (opt.isEmpty()) return;
        session.setAwaiting2fa(false);
        finalizeLogin(player, session, opt.get());
        plugin.sync(player, () -> plugin.messages().send(player, "login.success"));
        // Push integrations + release from limbo on the player thread.
        plugin.async(() -> {
            try { plugin.luckPerms().applyOffline(player); } catch (Throwable ignored) {}
            try { plugin.etcCoreBridge().publish(player, session); } catch (Throwable ignored) {}
        });
        plugin.sync(player, () -> plugin.limbo().releaseFromLimbo(player, session));
    }

    private void finalizeLogin(Player player, AuthSession session, Account acc) {
        session.setState(AuthState.OFFLINE_AUTHENTICATED);
        session.resetFailedAttempts();
        try {
            db.update(new Account(
                acc.getUuid(), acc.getUsername(), acc.getPasswordHash(),
                acc.isPremium(), acc.isLocked(),
                player.getAddress() != null ? player.getAddress().getAddress().getHostAddress() : null,
                System.currentTimeMillis(),
                acc.getCreatedEpochMs(),
                acc.getInventoryBlob(),
                acc.getTotpSecret(), acc.getSkinValue(), acc.getSkinSignature()));
        } catch (SQLException e) {
            plugin.getLogger().warning("Could not update last_login: " + e.getMessage());
        }
        recordIpSession(player);
        audit(player.getName(), "LOGIN", ipOf(player), null);
    }

    /** Stand-alone password verifier used by TwoFACommand for the disable flow. */
    public boolean verifyPassword(Account account, String password) {
        return account.getPasswordHash() != null && hasher.verify(password, account.getPasswordHash());
    }

    public enum LoginResult { OK, NEEDS_2FA, FAILED }

    public boolean changePassword(Player player, String oldPw, String newPw) {
        AuthSession session = getSession(player);
        if (session == null || session.isPremium()) return false;

        Optional<Account> opt = findAccount(player.getName());
        if (opt.isEmpty()) return false;

        Account acc = opt.get();
        if (!hasher.verify(oldPw, acc.getPasswordHash())) return false;

        try {
            db.update(new Account(
                acc.getUuid(), acc.getUsername(), hasher.hash(newPw),
                acc.isPremium(), acc.isLocked(),
                acc.getLastIp(), acc.getLastLoginEpochMs(),
                acc.getCreatedEpochMs(), acc.getInventoryBlob()));
            audit(player.getName(), "CHANGE_PASSWORD", ipOf(player), null);
            return true;
        } catch (SQLException e) {
            plugin.getLogger().severe("changePassword failed: " + e.getMessage());
            return false;
        }
    }

    public void logout(Player player) {
        AuthSession s = getSession(player);
        if (s == null) return;
        if (s.isPremium()) return;
        s.setState(AuthState.AWAITING_LOGIN);
        ipSessions.remove(player.getName().toLowerCase());
        audit(player.getName(), "LOGOUT", ipOf(player), null);
    }

    public boolean unregister(String username) {
        try {
            db.deleteByUsername(username);
            ipSessions.remove(username.toLowerCase());
            audit(username, "UNREGISTER", null, "admin");
            return true;
        } catch (SQLException e) {
            plugin.getLogger().severe("unregister failed: " + e.getMessage());
            return false;
        }
    }

    // -------------------------------------------------------------------
    // Premium take-over of an offline-registered name
    // -------------------------------------------------------------------

    /**
     * Called from {@link com.etcmc.etcauth.listener.JoinQuitListener} when
     * a verified-premium player joins with a username that already exists
     * as an offline account. The premium player gains the account and the
     * inventory; the offline owner is permanently locked out.
     *
     * <p>Must run on the player's region scheduler (item application is
     * region-bound).
     */
    public void claimForPremium(Player premiumPlayer, Account existing) {
        // Capture inventory of any *currently-online* offline-named
        // player (rare but possible if both somehow ended up online —
        // we kick them in PreLogin so this is mostly defensive).
        byte[] blob = existing.getInventoryBlob();

        // Replace the account with a premium-owned record. We delete by
        // username (offline UUID) and re-insert with the premium UUID so
        // future joins by the premium player are O(1) lookups.
        try {
            db.deleteByUsername(existing.getUsername());
            long now = System.currentTimeMillis();
            Account claimed = new Account(
                premiumPlayer.getUniqueId(),
                premiumPlayer.getName(),
                null,                       // premium = no password
                true,                       // premium flag
                false,                      // not locked
                premiumPlayer.getAddress() != null
                    ? premiumPlayer.getAddress().getAddress().getHostAddress() : null,
                now,
                existing.getCreatedEpochMs() == 0 ? now : existing.getCreatedEpochMs(),
                null);                      // inventory consumed by player
            db.insert(claimed);
            audit(premiumPlayer.getName(), "PREMIUM_CLAIM",
                premiumPlayer.getAddress() != null
                    ? premiumPlayer.getAddress().getAddress().getHostAddress() : null,
                "claimed-from-offline-uuid=" + existing.getUuid());
        } catch (SQLException e) {
            plugin.getLogger().severe("Premium claim failed: " + e.getMessage());
            return;
        }

        // Apply the inventory on the player's region thread.
        if (blob != null && blob.length > 0) {
            premiumPlayer.getScheduler().run(plugin, t -> {
                InventorySerializer.apply(premiumPlayer, blob);
                premiumPlayer.sendMessage(net.kyori.adventure.text.Component.text(
                    "[ETCAuth] Heredaste el inventario de la cuenta offline previamente registrada con tu nombre."));
            }, null);
        }
    }

    /**
     * Snapshot the inventory of an offline-authenticated player into
     * their account row, so that a future premium claim can grant it.
     * Cheap enough to call on every meaningful event (logout, periodic).
     */
    public void persistInventorySnapshot(Player p) {
        AuthSession s = getSession(p);
        if (s == null || s.isPremium() || !s.isAuthenticated()) return;

        Optional<Account> opt = findAccount(p.getName());
        if (opt.isEmpty()) return;
        Account acc = opt.get();
        byte[] blob = InventorySerializer.serialize(p);
        try {
            db.update(new Account(
                acc.getUuid(), acc.getUsername(), acc.getPasswordHash(),
                acc.isPremium(), acc.isLocked(),
                acc.getLastIp(), acc.getLastLoginEpochMs(),
                acc.getCreatedEpochMs(), blob));
        } catch (SQLException e) {
            plugin.getLogger().warning("Inventory snapshot failed: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------
    // IP-session helper (auto-login)
    // -------------------------------------------------------------------

    public boolean tryAutoLoginByIp(Player p) {
        if (!plugin.getConfig().getBoolean("auth.session-by-ip", true)) return false;
        IpSession s = ipSessions.get(p.getName().toLowerCase());
        if (s == null) return false;
        if (p.getAddress() == null) return false;
        if (!s.ip().equals(p.getAddress().getAddress().getHostAddress())) return false;
        long ttlMs = plugin.getConfig().getLong("auth.session-duration-minutes", 720) * 60_000L;
        if (System.currentTimeMillis() - s.timestampMs() > ttlMs) {
            ipSessions.remove(p.getName().toLowerCase());
            return false;
        }
        AuthSession session = getSession(p);
        if (session == null) return false;
        session.setState(AuthState.OFFLINE_AUTHENTICATED);
        return true;
    }

    private void recordIpSession(Player p) {
        if (p.getAddress() == null) return;
        ipSessions.put(p.getName().toLowerCase(),
            new IpSession(p.getUniqueId(),
                          p.getAddress().getAddress().getHostAddress(),
                          System.currentTimeMillis()));
    }

    public void shutdownAll() {
        // Persist inventory of every offline-authenticated player
        for (Player p : Bukkit.getOnlinePlayers()) {
            persistInventorySnapshot(p);
        }
        sessions.clear();
        ipSessions.clear();
    }

    private record IpSession(UUID uuid, String ip, long timestampMs) {}
}
