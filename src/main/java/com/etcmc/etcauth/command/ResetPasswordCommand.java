package com.etcmc.etcauth.command;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.auth.AuthState;
import com.etcmc.etcauth.database.Account;
import com.etcmc.etcauth.util.PasswordHasher;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Map;
import java.util.Optional;

/**
 * {@code /resetpassword <token> <newPassword>} — consume a recovery
 * token previously emailed by {@link ForgotPasswordCommand} and set a
 * new password.
 */
public final class ResetPasswordCommand implements CommandExecutor {

    private final ETCAuth plugin;
    private final AuthManager auth;
    private final PasswordHasher hasher;

    public ResetPasswordCommand(ETCAuth plugin, AuthManager auth, PasswordHasher hasher) {
        this.plugin = plugin;
        this.auth = auth;
        this.hasher = hasher;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player player)) { sender.sendMessage("Players only."); return true; }
        AuthSession s = auth.getSession(player.getUniqueId());
        if (s == null) return true;
        if (args.length < 2) {
            plugin.messages().send(player, "recovery.reset-usage");
            return true;
        }
        String token = args[0];
        String newPw = args[1];
        int min = plugin.getConfig().getInt("auth.password-min-length", 6);
        int max = plugin.getConfig().getInt("auth.password-max-length", 64);
        if (newPw.length() < min) {
            plugin.messages().send(player, "register.password-too-short", Map.of("min", String.valueOf(min)));
            return true;
        }
        if (newPw.length() > max) {
            plugin.messages().send(player, "register.password-too-long", Map.of("max", String.valueOf(max)));
            return true;
        }

        plugin.async(() -> {
            try {
                Optional<Account> opt = plugin.database().findByResetToken(token);
                if (opt.isEmpty()
                    || !opt.get().getUsername().equalsIgnoreCase(player.getName())
                    || opt.get().getResetTokenExpiresMs() < System.currentTimeMillis()) {
                    plugin.sync(player, () -> plugin.messages().send(player, "recovery.bad-token"));
                    return;
                }
                Account updated = opt.get()
                    .withPasswordHash(hasher.hash(newPw))
                    .withResetToken(null, 0L);
                plugin.database().update(updated);
                if (plugin.audit() != null) {
                    plugin.audit().log(player.getName(), "RECOVERY_COMPLETE", s.getIp(), null);
                }
                plugin.metrics().recoveryCompletions.incrementAndGet();
                plugin.sync(player, () -> {
                    plugin.messages().send(player, "recovery.reset-ok");
                    s.setState(AuthState.OFFLINE_AUTHENTICATED);
                    plugin.limbo().releaseFromLimbo(player, s);
                });
            } catch (Exception e) {
                plugin.getLogger().severe("resetpassword failed: " + e.getMessage());
            }
        });
        return true;
    }
}
