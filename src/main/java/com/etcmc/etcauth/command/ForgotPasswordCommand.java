package com.etcmc.etcauth.command;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.database.Account;
import com.etcmc.etcauth.recovery.EmailService;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * {@code /forgotpassword} — sends a one-time reset token to the email
 * address registered with {@code /setemail}. The token is valid for
 * {@code email.token-ttl-minutes} minutes.
 */
public final class ForgotPasswordCommand implements CommandExecutor {

    private final ETCAuth plugin;
    private final AuthManager auth;
    private final EmailService email;

    public ForgotPasswordCommand(ETCAuth plugin, AuthManager auth, EmailService email) {
        this.plugin = plugin;
        this.auth = auth;
        this.email = email;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player player)) { sender.sendMessage("Players only."); return true; }
        AuthSession s = auth.getSession(player.getUniqueId());
        if (s == null) return true;
        if (!email.enabled()) {
            plugin.messages().send(player, "recovery.disabled");
            return true;
        }
        plugin.metrics().recoveryRequests.incrementAndGet();
        plugin.async(() -> {
            Optional<Account> opt = auth.findAccount(player.getName());
            if (opt.isEmpty() || opt.get().getEmail() == null || opt.get().getEmail().isBlank()) {
                plugin.sync(player, () -> plugin.messages().send(player, "recovery.no-email"));
                return;
            }
            String token = EmailService.newToken();
            long expires = System.currentTimeMillis()
                + TimeUnit.MINUTES.toMillis(plugin.getConfig().getLong("email.token-ttl-minutes", 30));
            try {
                plugin.database().update(opt.get().withResetToken(token, expires));
                if (plugin.audit() != null) {
                    plugin.audit().log(player.getName(), "RECOVERY_REQUEST", s.getIp(), null);
                }
                String subject = "[ETCAuth] Reset your password";
                String body =
                    "Someone (hopefully you) requested a password reset for the\n"
                  + "account '" + player.getName() + "' on " + plugin.getServer().getName() + ".\n\n"
                  + "Run this in-game within "
                  + plugin.getConfig().getLong("email.token-ttl-minutes", 30) + " minutes:\n\n"
                  + "  /resetpassword " + token + " <new-password>\n\n"
                  + "If you did NOT request this, ignore the email — your password is unchanged.\n";
                boolean ok = email.send(opt.get().getEmail(), subject, body);
                plugin.sync(player, () -> plugin.messages().send(player,
                    ok ? "recovery.email-sent" : "recovery.email-fail",
                    Map.of("email", maskEmail(opt.get().getEmail()))));
            } catch (Exception e) {
                plugin.getLogger().severe("forgotpassword failed: " + e.getMessage());
            }
        });
        return true;
    }

    private static String maskEmail(String e) {
        int at = e.indexOf('@');
        if (at < 2) return "***";
        return e.charAt(0) + "***" + e.substring(at);
    }
}
