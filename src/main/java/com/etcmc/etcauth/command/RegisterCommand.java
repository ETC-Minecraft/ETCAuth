package com.etcmc.etcauth.command;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.auth.AuthState;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public final class RegisterCommand implements CommandExecutor {

    private final ETCAuth plugin;
    private final AuthManager auth;

    public RegisterCommand(ETCAuth plugin, AuthManager auth) {
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
            plugin.messages().send(player, "register.premium-cannot-register");
            return true;
        }
        if (s.getState() == AuthState.OFFLINE_AUTHENTICATED) {
            plugin.messages().send(player, "register.already-registered");
            return true;
        }
        if (args.length < 2) {
            plugin.messages().send(player, "register.usage");
            return true;
        }

        String pw = args[0];
        String confirm = args[1];

        if (!pw.equals(confirm)) {
            plugin.messages().send(player, "register.password-mismatch");
            return true;
        }

        int min = plugin.getConfig().getInt("auth.password-min-length", 6);
        int max = plugin.getConfig().getInt("auth.password-max-length", 64);
        if (pw.length() < min) {
            plugin.messages().send(player, "register.password-too-short",
                Map.of("min", String.valueOf(min)));
            return true;
        }
        if (pw.length() > max) {
            plugin.messages().send(player, "register.password-too-long",
                Map.of("max", String.valueOf(max)));
            return true;
        }

        // DB I/O off-main
        plugin.async(() -> {
            // Final guard against name-squatting: if Mojang says this name
            // belongs to a premium account, we refuse to register.
            try {
                Optional<UUID> premium = auth.resolvePremiumUuid(player.getName());
                if (premium.isPresent()) {
                    plugin.sync(player, () -> plugin.messages().send(player,
                        "register.name-is-premium",
                        Map.of("player", player.getName())));
                    return;
                }
            } catch (Exception ignored) {
                // Failed lookup => don't block registration
            }

            boolean ok = auth.register(player, pw);
            plugin.sync(player, () -> {
                if (ok) {
                    plugin.messages().send(player, "register.success");
                    plugin.async(() -> {
                        try { plugin.luckPerms().applyOffline(player); } catch (Throwable ignored) {}
                        try { plugin.etcCoreBridge().publish(player, s); } catch (Throwable ignored) {}
                    });
                } else {
                    plugin.messages().send(player, "register.already-registered");
                }
            });
        });

        return true;
    }
}
