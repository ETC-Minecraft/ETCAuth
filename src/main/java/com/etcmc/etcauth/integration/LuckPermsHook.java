package com.etcmc.etcauth.integration;

import com.etcmc.etcauth.ETCAuth;
import net.luckperms.api.LuckPerms;
import net.luckperms.api.LuckPermsProvider;
import net.luckperms.api.model.user.User;
import net.luckperms.api.node.Node;
import net.luckperms.api.node.types.InheritanceNode;
import org.bukkit.entity.Player;

import java.util.UUID;

/**
 * LuckPerms integration: when configured, automatically assign players
 * to a {@code premium-group} or {@code offline-group} the first time
 * their auth state is established.
 *
 * <p>If LuckPerms is missing, all operations no-op silently.
 */
public final class LuckPermsHook {

    private final ETCAuth plugin;
    private LuckPerms api;
    private boolean available;

    public LuckPermsHook(ETCAuth plugin) {
        this.plugin = plugin;
        try {
            this.api = LuckPermsProvider.get();
            this.available = true;
            plugin.getLogger().info("LuckPerms hook active.");
        } catch (Throwable t) {
            this.available = false;
        }
    }

    public boolean isAvailable() { return available; }

    public void applyPremium(Player p) {
        if (!available || !plugin.getConfig().getBoolean("luckperms.enabled", true)) return;
        String premiumGroup = plugin.getConfig().getString("luckperms.premium-group", "");
        String offlineGroup = plugin.getConfig().getString("luckperms.offline-group", "");

        if (!premiumGroup.isEmpty()) addGroup(p.getUniqueId(), premiumGroup);
        if (!offlineGroup.isEmpty()) removeGroup(p.getUniqueId(), offlineGroup);
    }

    public void applyOffline(Player p) {
        if (!available || !plugin.getConfig().getBoolean("luckperms.enabled", true)) return;
        String premiumGroup = plugin.getConfig().getString("luckperms.premium-group", "");
        String offlineGroup = plugin.getConfig().getString("luckperms.offline-group", "");

        if (!offlineGroup.isEmpty()) addGroup(p.getUniqueId(), offlineGroup);
        if (!premiumGroup.isEmpty()) removeGroup(p.getUniqueId(), premiumGroup);
    }

    private void addGroup(UUID uuid, String group) {
        api.getUserManager().modifyUser(uuid, (User u) -> {
            Node node = InheritanceNode.builder(group).build();
            u.data().add(node);
        });
    }

    private void removeGroup(UUID uuid, String group) {
        api.getUserManager().modifyUser(uuid, (User u) -> {
            Node node = InheritanceNode.builder(group).build();
            u.data().remove(node);
        });
    }
}
