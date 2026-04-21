package com.etcmc.etcauth.integration;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthSession;
import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.World;
import org.bukkit.WorldCreator;
import org.bukkit.entity.Player;

import java.lang.reflect.Method;
import java.util.concurrent.CompletableFuture;

/**
 * Quarantine world used to physically isolate unauthenticated players.
 *
 * <p>If {@code limbo.enabled} is {@code true}, every joining player whose
 * session is not yet authenticated is teleported to the limbo location.
 * On successful auth ({@link #releaseFromLimbo(Player, AuthSession)}) we
 * teleport them back to {@link AuthSession#getPreLimboLocation()}.
 *
 * <p>World resolution order:
 * <ol>
 *   <li>{@link Bukkit#getWorld(String)} — already loaded.</li>
 *   <li>If ETCWorlds is installed, reflectively call
 *       {@code ETCWorlds.get().worlds().loadWorld(name)} so the limbo
 *       can be a managed/instance world.</li>
 *   <li>Fall back to a plain {@link WorldCreator} so the admin doesn't
 *       have to install ETCWorlds for a basic setup.</li>
 * </ol>
 */
public final class Limbo {

    private final ETCAuth plugin;

    public Limbo(ETCAuth plugin) {
        this.plugin = plugin;
    }

    public boolean enabled() {
        return plugin.getConfig().getBoolean("limbo.enabled", false);
    }

    /** Resolve (and load if needed) the configured limbo world. May return null. */
    public World resolveWorld() {
        String name = plugin.getConfig().getString("limbo.world", "world");
        World w = Bukkit.getWorld(name);
        if (w != null) return w;

        // Try ETCWorlds via reflection so we don't compile-depend on it.
        if (Bukkit.getPluginManager().isPluginEnabled("ETCWorlds")) {
            try {
                Class<?> etcw = Class.forName("com.etcmc.etcworlds.ETCWorlds");
                Object instance = etcw.getMethod("get").invoke(null);
                Object manager = etcw.getMethod("worlds").invoke(instance);
                Method loadWorld = manager.getClass().getMethod("loadWorld", String.class);
                Object loaded = loadWorld.invoke(manager, name);
                if (loaded instanceof World lw) return lw;
            } catch (Throwable t) {
                plugin.getLogger().fine("ETCWorlds limbo bridge failed: " + t.getMessage());
            }
        }

        // Fallback: vanilla world creation.
        try {
            return new WorldCreator(name).createWorld();
        } catch (Throwable t) {
            plugin.getLogger().warning("Could not load/create limbo world '" + name + "': " + t.getMessage());
            return null;
        }
    }

    public Location resolveSpawn(World world) {
        double x = plugin.getConfig().getDouble("limbo.x", world.getSpawnLocation().getX());
        double y = plugin.getConfig().getDouble("limbo.y", world.getSpawnLocation().getY());
        double z = plugin.getConfig().getDouble("limbo.z", world.getSpawnLocation().getZ());
        float yaw = (float) plugin.getConfig().getDouble("limbo.yaw", 0d);
        float pitch = (float) plugin.getConfig().getDouble("limbo.pitch", 0d);
        return new Location(world, x, y, z, yaw, pitch);
    }

    /**
     * Send the player to the limbo location. Saves their current location
     * into {@code session.preLimboLocation} so it can be restored later.
     * No-op if limbo is disabled or the player is already in the limbo
     * world.
     */
    public void sendToLimbo(Player player, AuthSession session) {
        if (!enabled()) return;
        World world = resolveWorld();
        if (world == null) return;
        Location current = player.getLocation();
        if (world.equals(current.getWorld())) {
            // Player is already in limbo (possibly after a re-login). Don't
            // overwrite the saved pre-limbo location.
            return;
        }
        session.setPreLimboLocation(current.clone());
        Location target = resolveSpawn(world);
        // teleportAsync is the Folia-safe path.
        CompletableFuture<Boolean> f = player.teleportAsync(target);
        f.whenComplete((ok, err) -> {
            if (err != null) {
                plugin.getLogger().warning("Limbo teleport failed for "
                    + player.getName() + ": " + err.getMessage());
            }
        });
    }

    /**
     * Restore the player to {@code session.preLimboLocation} after they
     * successfully authenticate. No-op if there is nothing to restore.
     */
    public void releaseFromLimbo(Player player, AuthSession session) {
        if (!enabled()) return;
        Location target = session.getPreLimboLocation();
        if (target == null) return;
        session.setPreLimboLocation(null);
        player.teleportAsync(target).whenComplete((ok, err) -> {
            if (err != null) {
                plugin.getLogger().warning("Limbo release failed for "
                    + player.getName() + ": " + err.getMessage());
            }
        });
    }
}
