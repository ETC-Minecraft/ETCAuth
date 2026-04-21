package com.etcmc.etcauth.web;

import com.etcmc.etcauth.ETCAuth;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.bukkit.Bukkit;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Prometheus text-format exposition for ETCAuth.
 *
 * <p>Endpoint: {@code GET /metrics}. No auth required (it is normal
 * Prometheus practice to firewall the port instead). Adjust
 * {@code web.bind} and your firewall accordingly.
 */
public final class MetricsHandler implements HttpHandler {

    private final ETCAuth plugin;
    private final Metrics m;

    public MetricsHandler(ETCAuth plugin, Metrics m) {
        this.plugin = plugin;
        this.m = m;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        StringBuilder out = new StringBuilder(2048);

        int totalAccounts = 0, premiumAccounts = 0, totpEnabled = 0;
        try {
            totalAccounts   = plugin.database().countAccounts();
            premiumAccounts = plugin.database().countPremium();
            totpEnabled     = plugin.database().countTotpEnabled();
        } catch (Exception e) {
            plugin.getLogger().warning("Metrics DB query failed: " + e.getMessage());
        }

        long online = Bukkit.getOnlinePlayers().size();
        long authenticated = Bukkit.getOnlinePlayers().stream()
            .filter(p -> plugin.authManager().isAuthenticated(p))
            .count();

        gauge(out, "etcauth_accounts_total",
            "Total accounts in the database.", totalAccounts);
        gauge(out, "etcauth_accounts_premium",
            "Premium-owned accounts.", premiumAccounts);
        gauge(out, "etcauth_accounts_totp_enabled",
            "Accounts with TOTP/2FA enabled.", totpEnabled);
        gauge(out, "etcauth_players_online",
            "Players currently connected.", online);
        gauge(out, "etcauth_players_authenticated",
            "Connected players that have authenticated.", authenticated);

        counter(out, "etcauth_logins_ok_total",
            "Successful /login submissions.", m.loginsOk.get());
        counter(out, "etcauth_logins_failed_total",
            "Failed /login submissions.", m.loginsFail.get());
        counter(out, "etcauth_logins_needs_2fa_total",
            "Logins that prompted a 2FA challenge.", m.loginsNeeds2fa.get());
        counter(out, "etcauth_registrations_total",
            "Successful /register submissions.", m.registrations.get());
        counter(out, "etcauth_premium_claims_total",
            "Premium take-overs of an offline name.", m.premiumClaims.get());
        counter(out, "etcauth_recovery_requests_total",
            "/forgotpassword requests.", m.recoveryRequests.get());
        counter(out, "etcauth_recovery_completions_total",
            "/resetpassword completions.", m.recoveryCompletions.get());

        byte[] bytes = out.toString().getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "text/plain; version=0.0.4");
        ex.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    private static void gauge(StringBuilder sb, String name, String help, long value) {
        sb.append("# HELP ").append(name).append(' ').append(help).append('\n');
        sb.append("# TYPE ").append(name).append(" gauge\n");
        sb.append(name).append(' ').append(value).append('\n');
    }

    private static void counter(StringBuilder sb, String name, String help, long value) {
        sb.append("# HELP ").append(name).append(' ').append(help).append('\n');
        sb.append("# TYPE ").append(name).append(" counter\n");
        sb.append(name).append(' ').append(value).append('\n');
    }
}
