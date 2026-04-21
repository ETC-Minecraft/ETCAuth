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

public final class LoginCommand implements CommandExecutor {

    private final ETCAuth plugin;
    private final AuthManager auth;

    public LoginCommand(ETCAuth plugin, AuthManager auth) {
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
        if (s.isAuthenticated()) {
            plugin.messages().send(player, "login.already-logged-in");
            return true;
        }
        if (s.getState() == AuthState.AWAITING_REGISTER) {
            plugin.messages().send(player, "login.not-registered");
            return true;
        }
        if (args.length < 1) {
            plugin.messages().send(player, "login.usage");
            return true;
        }

        // Cooldown for failed attempts
        long now = System.currentTimeMillis();
        if (s.getFailedLockUntilMs() > now) {
            long secs = (s.getFailedLockUntilMs() - now) / 1000L;
            plugin.messages().send(player, "login.too-many-attempts",
                Map.of("time", String.valueOf(secs)));
            return true;
        }

        String pw = args[0];
        plugin.async(() -> {
            AuthManager.LoginResult res = auth.login(player, pw);
            plugin.sync(player, () -> {
                switch (res) {
                    case OK -> {
                        plugin.metrics().loginsOk.incrementAndGet();
                        plugin.messages().send(player, "login.success");
                        plugin.async(() -> {
                            try { plugin.luckPerms().applyOffline(player); } catch (Throwable ignored) {}
                            try { plugin.etcCoreBridge().publish(player, s); } catch (Throwable ignored) {}
                        });
                        plugin.limbo().releaseFromLimbo(player, s);
                    }
                    case NEEDS_2FA -> {
                        plugin.metrics().loginsNeeds2fa.incrementAndGet();
                        plugin.messages().send(player, "login.needs-2fa");
                    }
                    case FAILED -> {
                        plugin.metrics().loginsFail.incrementAndGet();
                        int attempts = s.incrementFailed();
                        int max = plugin.getConfig().getInt("auth.max-login-attempts", 5);
                        int remaining = Math.max(0, max - attempts);
                        if (attempts >= max) {
                            long cooldownMs = plugin.getConfig().getInt(
                                "auth.failed-attempt-cooldown-seconds", 300) * 1000L;
                            s.setFailedLockUntilMs(System.currentTimeMillis() + cooldownMs);
                            s.resetFailedAttempts();
                            player.kick(plugin.messages().kickMessage("login.too-many-attempts",
                                Map.of("time", String.valueOf(cooldownMs / 1000L))));
                        } else {
                            plugin.messages().send(player, "login.wrong-password",
                                Map.of("attempts", String.valueOf(remaining)));
                        }
                    }
                }
            });
        });

        return true;
    }
}
