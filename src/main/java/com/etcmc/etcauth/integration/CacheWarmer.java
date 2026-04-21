package com.etcmc.etcauth.integration;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.PremiumChecker;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * On startup, resolves the Mojang UUID for the most recently active
 * usernames so that the {@link PremiumChecker} cache is hot from the
 * very first connection of the day. Reduces user-visible latency for
 * the players who matter most.
 *
 * <p>Runs entirely on the async scheduler.
 */
public final class CacheWarmer {

    private final ETCAuth plugin;

    public CacheWarmer(ETCAuth plugin) { this.plugin = plugin; }

    public void warm() {
        if (!plugin.getConfig().getBoolean("premium.prewarm-cache", true)) return;
        int limit = plugin.getConfig().getInt("premium.prewarm-count", 100);

        plugin.async(() -> {
            List<String> names = topUsernames(limit);
            if (names.isEmpty()) return;
            int ok = 0, miss = 0, fail = 0;
            for (String name : names) {
                try {
                    if (plugin.premiumChecker().resolve(name).isPresent()) ok++;
                    else miss++;
                } catch (Exception e) {
                    fail++;
                }
                // gentle pacing — don't hammer Mojang
                try { Thread.sleep(120); } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt(); return;
                }
            }
            plugin.getLogger().info("[prewarm] resolved=" + ok
                + " not-premium=" + miss + " errors=" + fail);
        });
    }

    private List<String> topUsernames(int limit) {
        List<String> out = new ArrayList<>();
        String sql = "SELECT username FROM accounts ORDER BY last_login_ms DESC LIMIT ?";
        try (PreparedStatement ps = plugin.database().raw().prepareStatement(sql)) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(rs.getString("username"));
            }
        } catch (SQLException e) {
            plugin.getLogger().warning("[prewarm] query failed: " + e.getMessage());
        }
        return out;
    }
}
