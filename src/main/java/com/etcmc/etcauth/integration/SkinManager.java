package com.etcmc.etcauth.integration;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.database.Account;
import com.etcmc.etcauth.database.Database;
import com.destroystokyo.paper.profile.PlayerProfile;
import com.destroystokyo.paper.profile.ProfileProperty;
import org.bukkit.entity.Player;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Persists the Mojang skin (textures property) of players who have ever
 * logged in as premium, and re-applies it on subsequent joins so that
 * offline mode does not strip their custom appearance.
 *
 * <p>This is best-effort: failures are logged but never block the join
 * pipeline.
 */
public final class SkinManager {

    private static final Pattern VALUE_PROP = Pattern.compile(
        "\"name\"\\s*:\\s*\"textures\"\\s*,\\s*\"value\"\\s*:\\s*\"([^\"]+)\"" +
        "(?:\\s*,\\s*\"signature\"\\s*:\\s*\"([^\"]+)\")?");

    private final ETCAuth plugin;
    private final Database db;
    private final HttpClient http;

    public SkinManager(ETCAuth plugin, Database db) {
        this.plugin = plugin;
        this.db = db;
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(plugin.getConfig().getLong("premium.api-timeout-ms", 4000)))
            .build();
    }

    public boolean enabled() {
        return plugin.getConfig().getBoolean("skin.enabled", true);
    }

    /**
     * Re-apply a previously stored skin to {@code player}. Must be called
     * on the player's region scheduler.
     */
    public void apply(Player player, Account account) {
        if (!enabled()) return;
        if (account.getSkinValue() == null) return;
        try {
            PlayerProfile profile = player.getPlayerProfile();
            profile.removeProperty("textures");
            profile.setProperty(new ProfileProperty(
                "textures", account.getSkinValue(), account.getSkinSignature()));
            player.setPlayerProfile(profile);
        } catch (Throwable t) {
            plugin.getLogger().fine("Skin apply failed for " + player.getName() + ": " + t.getMessage());
        }
    }

    /**
     * Fetch the textures property from Mojang for the given uuid (must
     * be a premium account) and store it in the DB. Off-main only.
     */
    public void fetchAndStore(String username, java.util.UUID uuid) {
        if (!enabled()) return;
        try {
            String url = "https://sessionserver.mojang.com/session/minecraft/profile/"
                + uuid.toString().replace("-", "") + "?unsigned=false";
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(plugin.getConfig().getLong("premium.api-timeout-ms", 4000)))
                .GET().build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() != 200) return;
            Matcher m = VALUE_PROP.matcher(res.body());
            if (!m.find()) return;
            String value = m.group(1);
            String signature = m.group(2);
            Optional<Account> opt = db.findByUsername(username);
            if (opt.isEmpty()) return;
            db.update(opt.get().withSkin(value, signature));
        } catch (Throwable t) {
            plugin.getLogger().fine("Skin fetch failed for " + username + ": " + t.getMessage());
        }
    }

    /** Read raw bytes (kept for future re-use). */
    @SuppressWarnings("unused")
    private static String readAll(java.io.InputStream in) throws Exception {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line);
            return sb.toString();
        }
    }
}
