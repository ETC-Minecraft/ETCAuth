package com.etcmc.etcauth.integration;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.database.Account;
import me.clip.placeholderapi.expansion.PlaceholderExpansion;
import org.bukkit.OfflinePlayer;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Optional;

/**
 * PlaceholderAPI expansion exposing ETCAuth state to other plugins.
 *
 * <p>Available placeholders:
 * <ul>
 *   <li>{@code %etcauth_premium%}     — true/false</li>
 *   <li>{@code %etcauth_state%}       — current AuthState name</li>
 *   <li>{@code %etcauth_authenticated%} — true/false</li>
 *   <li>{@code %etcauth_lastip%}      — last known IP</li>
 *   <li>{@code %etcauth_lastlogin%}   — formatted timestamp</li>
 *   <li>{@code %etcauth_account_age_days%} — int days since creation</li>
 *   <li>{@code %etcauth_registered%}  — true/false</li>
 * </ul>
 */
public final class ETCAuthExpansion extends PlaceholderExpansion {

    private final ETCAuth plugin;
    private final SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public ETCAuthExpansion(ETCAuth plugin) { this.plugin = plugin; }

    @Override public String getIdentifier() { return "etcauth"; }
    @Override public String getAuthor()     { return "ETCMC"; }
    @Override public String getVersion()    { return plugin.getDescription().getVersion(); }
    @Override public boolean persist()      { return true; }

    @Override
    public String onRequest(OfflinePlayer player, String params) {
        if (player == null) return "";
        AuthSession session = plugin.authManager().getSession(player.getUniqueId());
        Optional<Account> opt = plugin.authManager().findAccount(player.getName());

        return switch (params.toLowerCase()) {
            case "premium"           -> session != null && session.isPremium() ? "true" : "false";
            case "state"             -> session == null ? "OFFLINE" : session.getState().name();
            case "authenticated"     -> session != null && session.isAuthenticated() ? "true" : "false";
            case "registered"        -> opt.isPresent() ? "true" : "false";
            case "lastip"            -> opt.map(a -> nz(a.getLastIp())).orElse("");
            case "lastlogin"         -> opt.map(a -> a.getLastLoginEpochMs() > 0
                                                    ? fmt.format(new Date(a.getLastLoginEpochMs()))
                                                    : "").orElse("");
            case "account_age_days"  -> opt.map(a -> {
                if (a.getCreatedEpochMs() == 0) return "0";
                long days = (System.currentTimeMillis() - a.getCreatedEpochMs()) / 86_400_000L;
                return String.valueOf(days);
            }).orElse("0");
            default -> null;
        };
    }

    private static String nz(String s) { return s == null ? "" : s; }
}
