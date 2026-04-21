package com.etcmc.etcauth.listener;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import io.papermc.paper.event.player.AsyncChatEvent;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerMoveEvent;

import java.util.List;
import java.util.Locale;

/**
 * Blocks gameplay actions while a player is not authenticated.
 *
 * <p>All registered handlers are LOWEST priority and bail out as fast
 * as possible for authenticated players to avoid runtime overhead on
 * the hot path.
 */
public final class RestrictionListener implements Listener {

    private final ETCAuth plugin;
    private final AuthManager auth;

    public RestrictionListener(ETCAuth plugin, AuthManager auth) {
        this.plugin = plugin;
        this.auth = auth;
    }

    private boolean needsBlock(Player p) {
        AuthSession s = auth.getSession(p.getUniqueId());
        return s != null && !s.isAuthenticated();
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent ev) {
        if (!plugin.getConfig().getBoolean("restrictions.block-movement", true)) return;
        Player p = ev.getPlayer();
        if (!needsBlock(p)) return;

        // Allow head rotation, block positional movement
        if (ev.getFrom().getX() == ev.getTo().getX()
            && ev.getFrom().getY() == ev.getTo().getY()
            && ev.getFrom().getZ() == ev.getTo().getZ()) return;

        ev.setTo(ev.getFrom());
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onChat(AsyncChatEvent ev) {
        if (!plugin.getConfig().getBoolean("restrictions.block-chat", true)) return;
        if (!needsBlock(ev.getPlayer())) return;
        ev.setCancelled(true);
        plugin.messages().send(ev.getPlayer(), "restriction.blocked");
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent ev) {
        if (!plugin.getConfig().getBoolean("restrictions.block-commands", true)) return;
        if (!needsBlock(ev.getPlayer())) return;

        String raw = ev.getMessage();
        if (raw.startsWith("/")) raw = raw.substring(1);
        String cmd = raw.split(" ", 2)[0].toLowerCase(Locale.ROOT);

        List<String> allowed = plugin.getConfig().getStringList("restrictions.allowed-commands");
        for (String a : allowed) {
            if (a.equalsIgnoreCase(cmd)) return;
        }

        ev.setCancelled(true);
        plugin.messages().send(ev.getPlayer(), "restriction.blocked");
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDamage(EntityDamageEvent ev) {
        if (!plugin.getConfig().getBoolean("restrictions.block-damage", true)) return;
        if (!(ev.getEntity() instanceof Player p)) return;
        if (!needsBlock(p)) return;
        ev.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent ev) {
        if (!plugin.getConfig().getBoolean("restrictions.block-interact", true)) return;
        if (!needsBlock(ev.getPlayer())) return;
        ev.setCancelled(true);
    }
}
