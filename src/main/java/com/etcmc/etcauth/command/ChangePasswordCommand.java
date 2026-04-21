package com.etcmc.etcauth.command;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Map;

public final class ChangePasswordCommand implements CommandExecutor {

    private final ETCAuth plugin;
    private final AuthManager auth;

    public ChangePasswordCommand(ETCAuth plugin, AuthManager auth) {
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
        if (s == null) return true;
        if (s.isPremium()) {
            plugin.messages().send(player, "change-password.premium-no-password");
            return true;
        }
        if (!s.isAuthenticated()) {
            plugin.messages().send(player, "restriction.blocked");
            return true;
        }
        if (args.length < 2) {
            plugin.messages().send(player, "change-password.usage");
            return true;
        }

        String oldPw = args[0];
        String newPw = args[1];

        int min = plugin.getConfig().getInt("auth.password-min-length", 6);
        int max = plugin.getConfig().getInt("auth.password-max-length", 64);
        if (newPw.length() < min) {
            plugin.messages().send(player, "register.password-too-short",
                Map.of("min", String.valueOf(min)));
            return true;
        }
        if (newPw.length() > max) {
            plugin.messages().send(player, "register.password-too-long",
                Map.of("max", String.valueOf(max)));
            return true;
        }

        plugin.async(() -> {
            boolean ok = auth.changePassword(player, oldPw, newPw);
            plugin.sync(player, () -> {
                if (ok) plugin.messages().send(player, "change-password.success");
                else    plugin.messages().send(player, "change-password.wrong-old");
            });
        });

        return true;
    }
}
