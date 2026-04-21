package com.etcmc.etcauth.packets;

import com.etcmc.etcauth.ETCAuth;
import com.github.retrooper.packetevents.PacketEvents;
import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketListenerPriority;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.wrapper.login.client.WrapperLoginClientLoginStart;
import io.github.retrooper.packetevents.factory.spigot.SpigotPacketEventsBuilder;

import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Optional PacketEvents-based hardening layer.
 *
 * <p>This runs at the lowest possible level (Netty handshake) and does
 * three things <b>before</b> the player object exists or PreLogin fires:
 *
 * <ol>
 *   <li><b>Rate-limit</b> connection attempts per IP — kicks an IP that
 *       opens more than {@code packets.max-attempts-per-window} login
 *       handshakes within {@code packets.window-seconds}. This shuts down
 *       the simplest credential-stuffing and reconnect-spam bots.</li>
 *   <li><b>Username sanity check</b> — rejects names with characters
 *       Mojang does not allow ({@code [^A-Za-z0-9_]}) or wrong length
 *       (must be 1..16). Prevents nameless / unicode / SQL-flavoured
 *       impersonation attempts well before they hit our DAO.</li>
 *   <li><b>Connection logging</b> — every successful handshake is logged
 *       with IP for forensic auditing.</li>
 * </ol>
 *
 * <p>Initialised lazily: if PacketEvents is not present on the server,
 * {@link #tryEnable(ETCAuth)} silently no-ops.
 */
public final class PacketHook {

    private static final Pattern VALID_NAME = Pattern.compile("^[A-Za-z0-9_]{1,16}$");

    private final ETCAuth plugin;
    private final ConcurrentHashMap<String, IpStats> stats = new ConcurrentHashMap<>();
    private final long windowMs;
    private final int maxAttempts;
    private final long banMs;

    private PacketHook(ETCAuth plugin) {
        this.plugin = plugin;
        this.windowMs    = plugin.getConfig().getLong("packets.window-seconds", 30) * 1000L;
        this.maxAttempts = plugin.getConfig().getInt("packets.max-attempts-per-window", 5);
        this.banMs       = plugin.getConfig().getLong("packets.cooldown-seconds", 120) * 1000L;
    }

    /**
     * Try to initialise the PacketEvents integration. Returns {@code true}
     * on success, {@code false} if PacketEvents is not on the classpath or
     * the integration is disabled in config.
     */
    public static boolean tryEnable(ETCAuth plugin) {
        if (!plugin.getConfig().getBoolean("packets.enabled", true)) {
            return false;
        }
        try {
            Class.forName("com.github.retrooper.packetevents.PacketEvents");
        } catch (ClassNotFoundException e) {
            plugin.getLogger().info("PacketEvents not detected — skipping packet-level hardening.");
            return false;
        }

        PacketHook hook = new PacketHook(plugin);
        try {
            PacketEvents.setAPI(SpigotPacketEventsBuilder.build(plugin));
            PacketEvents.getAPI().getSettings()
                .checkForUpdates(false)
                .reEncodeByDefault(false);
            PacketEvents.getAPI().load();
            PacketEvents.getAPI().getEventManager().registerListener(hook.buildListener());
            PacketEvents.getAPI().init();
            plugin.getLogger().info("PacketEvents hook active — early-handshake protection enabled.");
            return true;
        } catch (Throwable t) {
            plugin.getLogger().warning("Failed to initialise PacketEvents: " + t.getMessage());
            return false;
        }
    }

    public static void disable() {
        try {
            if (PacketEvents.getAPI() != null) PacketEvents.getAPI().terminate();
        } catch (Throwable ignored) { }
    }

    private PacketListenerAbstract buildListener() {
        PacketHook self = this;
        return new PacketListenerAbstract(PacketListenerPriority.LOWEST) {
            @Override
            public void onPacketReceive(PacketReceiveEvent event) {
                if (event.getPacketType() != PacketType.Login.Client.LOGIN_START) return;

                WrapperLoginClientLoginStart wrapper =
                    new WrapperLoginClientLoginStart(event);
                String username = wrapper.getUsername();
                String ip = self.extractIp(event);

                // --- 1) Username sanity ---
                if (username == null || !VALID_NAME.matcher(username).matches()) {
                    self.plugin.getLogger().warning(
                        "[packets] Rejected handshake: invalid username from " + ip);
                    event.setCancelled(true);
                    return;
                }

                // --- 2) Rate-limit per IP ---
                long now = System.currentTimeMillis();
                IpStats s = self.stats.computeIfAbsent(ip, k -> new IpStats());
                synchronized (s) {
                    if (s.bannedUntilMs > now) {
                        event.setCancelled(true);
                        return;
                    }
                    if (now - s.windowStartMs > self.windowMs) {
                        s.windowStartMs = now;
                        s.attempts = 0;
                    }
                    s.attempts++;
                    if (s.attempts > self.maxAttempts) {
                        s.bannedUntilMs = now + self.banMs;
                        self.plugin.getLogger().warning(
                            "[packets] Rate-limit triggered for IP " + ip
                            + " (locked " + (self.banMs / 1000) + "s)");
                        event.setCancelled(true);
                        return;
                    }
                }

                // --- 3) Audit log ---
                self.plugin.getLogger().info(
                    "[packets] handshake user=" + username + " ip=" + ip);
            }
        };
    }

    private String extractIp(PacketReceiveEvent ev) {
        Object addr = ev.getUser().getAddress();
        if (addr instanceof InetSocketAddress isa) {
            return isa.getAddress().getHostAddress();
        }
        return "unknown";
    }

    private static final class IpStats {
        long windowStartMs = System.currentTimeMillis();
        int attempts = 0;
        long bannedUntilMs = 0L;
    }
}
