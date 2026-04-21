package com.etcmc.etcauth.web;

import com.etcmc.etcauth.ETCAuth;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Read-only HTML dashboard. Protected by HTTP Basic auth using
 * {@code web.dashboard-username} / {@code web.dashboard-password} from
 * config. If either is empty the dashboard refuses to serve.
 */
public final class DashboardHandler implements HttpHandler {

    private final ETCAuth plugin;

    public DashboardHandler(ETCAuth plugin) {
        this.plugin = plugin;
    }

    @Override
    public void handle(HttpExchange ex) throws IOException {
        String user = plugin.getConfig().getString("web.dashboard-username", "");
        String pass = plugin.getConfig().getString("web.dashboard-password", "");
        if (user.isEmpty() || pass.isEmpty()) {
            send(ex, 503, "Dashboard disabled: configure web.dashboard-username/password.");
            return;
        }
        if (!checkBasicAuth(ex, user, pass)) {
            ex.getResponseHeaders().add("WWW-Authenticate", "Basic realm=\"ETCAuth\"");
            send(ex, 401, "Unauthorized");
            return;
        }
        try {
            send(ex, 200, render());
        } catch (Exception e) {
            plugin.getLogger().warning("Dashboard render failed: " + e.getMessage());
            send(ex, 500, "Internal error");
        }
    }

    private boolean checkBasicAuth(HttpExchange ex, String user, String pass) {
        List<String> auth = ex.getRequestHeaders().get("Authorization");
        if (auth == null || auth.isEmpty()) return false;
        String header = auth.get(0);
        if (!header.startsWith("Basic ")) return false;
        try {
            String decoded = new String(
                Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon < 0) return false;
            return user.equals(decoded.substring(0, colon))
                && pass.equals(decoded.substring(colon + 1));
        } catch (Throwable t) {
            return false;
        }
    }

    private String render() throws Exception {
        int total = plugin.database().countAccounts();
        int premium = plugin.database().countPremium();
        int totp = plugin.database().countTotpEnabled();

        StringBuilder sb = new StringBuilder(8192);
        sb.append("<!doctype html><html><head><meta charset=utf-8>")
          .append("<title>ETCAuth Dashboard</title>")
          .append("<style>")
          .append("body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1115;color:#e6e8ec;}")
          .append("header{background:linear-gradient(90deg,#ffaa00,#ff5555);padding:1.25rem 2rem;color:#1a1a1a;}")
          .append("h1{margin:0;font-size:1.5rem;}h2{margin-top:2rem;border-bottom:1px solid #2a2f3a;padding-bottom:.4rem;}")
          .append("main{padding:1.5rem 2rem;max-width:1100px;margin:auto;}")
          .append(".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;}")
          .append(".card{background:#171a22;border:1px solid #232838;border-radius:.6rem;padding:1rem;}")
          .append(".card .v{font-size:1.7rem;font-weight:600;color:#ffaa00;}")
          .append("table{width:100%;border-collapse:collapse;font-size:.92rem;}")
          .append("th,td{padding:.45rem .6rem;border-bottom:1px solid #232838;text-align:left;}")
          .append("th{color:#9aa3b2;font-weight:500;}")
          .append(".pill{display:inline-block;padding:.1rem .55rem;border-radius:1rem;font-size:.78rem;}")
          .append(".pill.ok{background:#13452a;color:#4ade80;}")
          .append(".pill.warn{background:#4a3b14;color:#fbbf24;}")
          .append(".pill.bad{background:#4a1414;color:#f87171;}")
          .append("</style></head><body>")
          .append("<header><h1>ETCAuth Dashboard</h1></header>")
          .append("<main>");

        sb.append("<div class=cards>")
          .append(card("Cuentas", total))
          .append(card("Premium", premium))
          .append(card("Con 2FA", totp))
          .append(card("Online", Bukkit.getOnlinePlayers().size()))
          .append("</div>");

        sb.append("<h2>Jugadores conectados</h2>");
        sb.append("<table><tr><th>Nombre</th><th>UUID</th><th>Estado</th><th>IP</th></tr>");
        for (Player p : Bukkit.getOnlinePlayers()) {
            var s = plugin.authManager().getSession(p.getUniqueId());
            String state = s == null ? "?" : s.getState().name();
            String klass = s != null && s.isAuthenticated() ? "ok"
                : s != null && s.isAwaiting2fa() ? "warn" : "bad";
            String ip = p.getAddress() != null ? p.getAddress().getAddress().getHostAddress() : "?";
            sb.append("<tr><td>").append(esc(p.getName())).append("</td>")
              .append("<td>").append(p.getUniqueId()).append("</td>")
              .append("<td><span class='pill ").append(klass).append("'>")
              .append(esc(state)).append("</span></td>")
              .append("<td>").append(esc(ip)).append("</td></tr>");
        }
        sb.append("</table>");

        if (plugin.audit() != null) {
            sb.append("<h2>Eventos recientes</h2>");
            var entries = plugin.audit().recentAll(50);
            sb.append("<table><tr><th>Tiempo</th><th>Usuario</th><th>Evento</th><th>IP</th><th>Detalle</th></tr>");
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            for (var e : entries) {
                sb.append("<tr><td>").append(fmt.format(new Date(e.ts()))).append("</td>")
                  .append("<td>").append(esc(e.username())).append("</td>")
                  .append("<td>").append(esc(e.event())).append("</td>")
                  .append("<td>").append(esc(String.valueOf(e.ip()))).append("</td>")
                  .append("<td>").append(esc(String.valueOf(e.detail()))).append("</td></tr>");
            }
            sb.append("</table>");
        }

        sb.append("</main></body></html>");
        return sb.toString();
    }

    private static String card(String label, long value) {
        return "<div class=card><div>" + label + "</div><div class=v>" + value + "</div></div>";
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type",
            code == 200 ? "text/html; charset=utf-8" : "text/plain; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }
}
