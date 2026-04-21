package com.etcmc.etcauth.web;

import com.etcmc.etcauth.ETCAuth;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * Embedded HTTP server hosting the metrics endpoint and the read-only
 * dashboard. Uses {@link com.sun.net.httpserver.HttpServer} so we don't
 * pull in a web framework dependency.
 *
 * <p>Disabled when {@code web.enabled=false}. Bind defaults to
 * {@code 127.0.0.1:9229} which is safe for local Prometheus scraping
 * behind a reverse proxy. Set {@code web.bind} to {@code 0.0.0.0} only
 * if you actually want public access (then make sure to set the
 * dashboard credentials).
 */
public final class HttpServerHook {

    private final ETCAuth plugin;
    private final Metrics metrics;
    private HttpServer server;

    public HttpServerHook(ETCAuth plugin, Metrics metrics) {
        this.plugin = plugin;
        this.metrics = metrics;
    }

    public void start() {
        if (!plugin.getConfig().getBoolean("web.enabled", false)) return;
        String bind = plugin.getConfig().getString("web.bind", "127.0.0.1");
        int port = plugin.getConfig().getInt("web.port", 9229);
        try {
            server = HttpServer.create(new InetSocketAddress(bind, port), 0);
            server.createContext("/metrics", new MetricsHandler(plugin, metrics));
            server.createContext("/", new DashboardHandler(plugin));
            server.setExecutor(Executors.newFixedThreadPool(2, r -> {
                Thread t = new Thread(r, "ETCAuth-Web");
                t.setDaemon(true);
                return t;
            }));
            server.start();
            plugin.getLogger().info("HTTP server listening on " + bind + ":" + port);
        } catch (Exception e) {
            plugin.getLogger().warning("HTTP server failed to start: " + e.getMessage());
        }
    }

    public void stop() {
        if (server != null) {
            try { server.stop(0); } catch (Throwable ignored) {}
            server = null;
        }
    }
}
