package com.etcmc.etcauth.command;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

public final class LogoutCommand implements CommandExecutor {

    private final ETCAuth plugin;
    private final AuthManager auth;

    public LogoutCommand(ETCAuth plugin, AuthManager auth) {
        this.plugin = plugin;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("Players only.");
            return true;
        }

        AuthSession s = auth.getSession(player.getUniqueId());
        if (s == null || !s.isAuthenticated() || s.isPremium()) {
            plugin.messages().send(player, "logout.not-logged-in");
            return true;
        }

        plugin.async(() -> {
            auth.persistInventorySnapshot(player);
            auth.logout(player);
            plugin.sync(player, () -> plugin.messages().send(player, "logout.success"));
        });
        return true;
    }
}
