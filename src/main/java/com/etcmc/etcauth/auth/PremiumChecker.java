package com.etcmc.etcauth.auth;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves a username to its canonical premium UUID using Mojang's API.
 *
 * <p>Returns {@link Optional#empty()} when the name is not registered as
 * a premium account (HTTP 204/404), and throws on transport errors so
 * the caller can decide whether to fail-open or fail-closed.
 *
 * <p>Results are cached in-memory for the configured TTL.
 */
public final class PremiumChecker {

    private static final String API_URL =
        "https://api.mojang.com/users/profiles/minecraft/";

    private final HttpClient http;
    private final long cacheMs;
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public PremiumChecker(long timeoutMs, long cacheMinutes) {
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(timeoutMs))
            .build();
        this.cacheMs = cacheMinutes * 60_000L;
    }

    /**
     * @return the premium UUID for {@code username}, or empty if Mojang
     *         reports the name does not belong to a paid account.
     */
    public Optional<UUID> resolve(String username) throws Exception {
        String key = username.toLowerCase();
        CacheEntry hit = cache.get(key);
        long now = System.currentTimeMillis();
        if (hit != null && hit.expiresAt > now) {
            return Optional.ofNullable(hit.uuid);
        }

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(API_URL + username))
            .timeout(Duration.ofMillis(4000))
            .GET()
            .build();

        HttpResponse<java.io.InputStream> resp = http.send(
            req, HttpResponse.BodyHandlers.ofInputStream());

        if (resp.statusCode() == 204 || resp.statusCode() == 404) {
            cache.put(key, new CacheEntry(null, now + cacheMs));
            return Optional.empty();
        }
        if (resp.statusCode() != 200) {
            throw new RuntimeException(
                "Mojang API returned HTTP " + resp.statusCode());
        }

        try (var reader = new InputStreamReader(resp.body())) {
            JsonObject json = JsonParser.parseReader(reader).getAsJsonObject();
            String raw = json.get("id").getAsString();
            UUID uuid = parseUuid(raw);
            cache.put(key, new CacheEntry(uuid, now + cacheMs));
            return Optional.of(uuid);
        }
    }

    public void invalidate(String username) {
        cache.remove(username.toLowerCase());
    }

    private static UUID parseUuid(String raw) {
        // Mojang returns UUID without dashes
        String dashed = raw.substring(0, 8) + "-"
                      + raw.substring(8, 12) + "-"
                      + raw.substring(12, 16) + "-"
                      + raw.substring(16, 20) + "-"
                      + raw.substring(20);
        return UUID.fromString(dashed);
    }

    private record CacheEntry(UUID uuid, long expiresAt) {}
}
