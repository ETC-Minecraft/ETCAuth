package com.etcmc.etcauth.command;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.database.Account;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * {@code /setemail <email>} — register or update the recovery email
 * address. Player must be authenticated.
 */
public final class SetEmailCommand implements CommandExecutor {

    private static final Pattern EMAIL = Pattern.compile(
        "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private final ETCAuth plugin;
    private final AuthManager auth;

    public SetEmailCommand(ETCAuth plugin, AuthManager auth) {
        this.plugin = plugin;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player player)) { sender.sendMessage("Players only."); return true; }
        AuthSession s = auth.getSession(player.getUniqueId());
        if (s == null || !s.isAuthenticated()) {
            plugin.messages().send(player, "recovery.must-be-logged-in");
            return true;
        }
        if (s.isPremium()) {
            plugin.messages().send(player, "recovery.premium-no-email");
            return true;
        }
        if (args.length < 1) {
            plugin.messages().send(player, "recovery.setemail-usage");
            return true;
        }
        String email = args[0];
        if (!EMAIL.matcher(email).matches()) {
            plugin.messages().send(player, "recovery.bad-email");
            return true;
        }
        plugin.async(() -> {
            Optional<Account> opt = auth.findAccount(player.getName());
            if (opt.isEmpty()) return;
            try {
                plugin.database().update(opt.get().withEmail(email));
                if (plugin.audit() != null) {
                    plugin.audit().log(player.getName(), "EMAIL_SET", s.getIp(), null);
                }
                plugin.sync(player, () -> plugin.messages().send(player,
                    "recovery.email-saved", Map.of("email", email)));
            } catch (Exception e) {
                plugin.getLogger().severe("setemail failed: " + e.getMessage());
            }
        });
        return true;
    }
}
