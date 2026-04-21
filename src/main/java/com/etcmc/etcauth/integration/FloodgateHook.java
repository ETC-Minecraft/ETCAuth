package com.etcmc.etcauth.integration;

import org.bukkit.Bukkit;
import org.geysermc.floodgate.api.FloodgateApi;

import java.util.UUID;

/**
 * Floodgate / Geyser integration.
 *
 * <p>Bedrock players that connect through Geyser are authenticated by
 * Microsoft (Xbox Live) before Floodgate even sees them — there is no
 * realistic "cracked Bedrock" client. ETCAuth therefore treats every
 * Floodgate-detected UUID as premium-equivalent: no password is ever
 * required and they bypass the {@code AwaitingLogin}/{@code AwaitingRegister}
 * flow entirely.
 *
 * <p>If Floodgate is not installed, all checks return {@code false}.
 */
public final class FloodgateHook {

    private static Boolean available;   // tri-state cache

    private FloodgateHook() {}

    public static boolean isAvailable() {
        if (available != null) return available;
        try {
            Class.forName("org.geysermc.floodgate.api.FloodgateApi");
            available = Bukkit.getPluginManager().getPlugin("floodgate") != null;
        } catch (ClassNotFoundException e) {
            available = false;
        }
        return available;
    }

    /** @return true if {@code uuid} corresponds to a Bedrock player. */
    public static boolean isBedrock(UUID uuid) {
        if (!isAvailable()) return false;
        try {
            return FloodgateApi.getInstance().isFloodgatePlayer(uuid);
        } catch (Throwable t) {
            return false;
        }
    }

    /** @return true if a username starts with the Floodgate prefix (e.g. {@code .Player}). */
    public static boolean isBedrockUsername(String username) {
        if (!isAvailable()) return false;
        try {
            String prefix = FloodgateApi.getInstance().getPlayerPrefix();
            return username != null && !prefix.isEmpty() && username.startsWith(prefix);
        } catch (Throwable t) {
            return false;
        }
    }
}
