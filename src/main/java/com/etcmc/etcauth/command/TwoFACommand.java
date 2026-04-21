package com.etcmc.etcauth.command;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.database.Account;
import com.etcmc.etcauth.util.TotpUtil;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.format.NamedTextColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Player-facing 2FA command.
 *
 * <ul>
 *   <li>{@code /2fa setup}             — generate a secret + show otpauth URI</li>
 *   <li>{@code /2fa confirm <code>}    — confirm setup with a TOTP code</li>
 *   <li>{@code /2fa disable <password>} — remove 2FA after password check</li>
 *   <li>{@code /2fa <code>}            — submit code during the login flow</li>
 * </ul>
 */
public final class TwoFACommand implements CommandExecutor {

    private final ETCAuth plugin;
    private final AuthManager auth;

    /** uuid -> pending (un-confirmed) secret. */
    private final ConcurrentHashMap<java.util.UUID, String> pending = new ConcurrentHashMap<>();

    public TwoFACommand(ETCAuth plugin, AuthManager auth) {
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

        if (args.length == 0) {
            plugin.messages().send(player, "twofa.usage");
            return true;
        }

        // Login-flow code submission: any 6-digit input while awaiting 2FA.
        if (s.isAwaiting2fa() && args[0].matches("\\d{6}")) {
            handleLoginCode(player, s, args[0]);
            return true;
        }

        switch (args[0].toLowerCase()) {
            case "setup"   -> handleSetup(player, s);
            case "confirm" -> handleConfirm(player, s, args);
            case "disable" -> handleDisable(player, s, args);
            default        -> plugin.messages().send(player, "twofa.usage");
        }
        return true;
    }

    // ---- setup / confirm / disable ----

    private void handleSetup(Player player, AuthSession s) {
        if (!s.isAuthenticated() || s.isAwaiting2fa()) {
            plugin.messages().send(player, "twofa.must-be-logged-in");
            return;
        }
        plugin.async(() -> {
            Optional<Account> opt = auth.findAccount(player.getName());
            if (opt.isEmpty()) return;
            if (opt.get().getTotpSecret() != null) {
                plugin.sync(player, () -> plugin.messages().send(player, "twofa.already-enabled"));
                return;
            }
            String secret = TotpUtil.newSecret();
            pending.put(player.getUniqueId(), secret);
            String uri = TotpUtil.otpauthUri("ETCAuth", player.getName(), secret);
            plugin.sync(player, () -> {
                plugin.messages().send(player, "twofa.setup-secret",
                    Map.of("secret", secret));
                player.sendMessage(Component.text(uri, NamedTextColor.AQUA)
                    .clickEvent(ClickEvent.copyToClipboard(uri)));
                plugin.messages().send(player, "twofa.setup-confirm-hint");
            });
        });
    }

    private void handleConfirm(Player player, AuthSession s, String[] args) {
        if (args.length < 2) { plugin.messages().send(player, "twofa.usage"); return; }
        String secret = pending.get(player.getUniqueId());
        if (secret == null) { plugin.messages().send(player, "twofa.no-pending-setup"); return; }
        if (!TotpUtil.verify(secret, args[1])) {
            plugin.messages().send(player, "twofa.bad-code");
            return;
        }
        plugin.async(() -> {
            Optional<Account> opt = auth.findAccount(player.getName());
            if (opt.isEmpty()) return;
            try {
                plugin.database().update(opt.get().withTotpSecret(secret));
                pending.remove(player.getUniqueId());
                if (plugin.audit() != null) {
                    plugin.audit().log(player.getName(), "TOTP_ENABLE",
                        s.getIp(), null);
                }
                plugin.sync(player, () -> plugin.messages().send(player, "twofa.enabled"));
            } catch (Exception e) {
                plugin.getLogger().severe("TOTP confirm failed: " + e.getMessage());
            }
        });
    }

    private void handleDisable(Player player, AuthSession s, String[] args) {
        if (s.isPremium()) {
            plugin.messages().send(player, "twofa.premium-no-password");
            return;
        }
        if (args.length < 2) { plugin.messages().send(player, "twofa.usage"); return; }
        String pw = args[1];
        plugin.async(() -> {
            Optional<Account> opt = auth.findAccount(player.getName());
            if (opt.isEmpty() || opt.get().getTotpSecret() == null) {
                plugin.sync(player, () -> plugin.messages().send(player, "twofa.not-enabled"));
                return;
            }
            // Verify password by attempting a hash-only check.
            if (!auth.verifyPassword(opt.get(), pw)) {
                plugin.sync(player, () -> plugin.messages().send(player, "twofa.wrong-password"));
                return;
            }
            try {
                plugin.database().update(opt.get().withTotpSecret(null));
                if (plugin.audit() != null) {
                    plugin.audit().log(player.getName(), "TOTP_DISABLE",
                        s.getIp(), null);
                }
                plugin.sync(player, () -> plugin.messages().send(player, "twofa.disabled"));
            } catch (Exception e) {
                plugin.getLogger().severe("TOTP disable failed: " + e.getMessage());
            }
        });
    }

    // ---- login-flow code ----

    private void handleLoginCode(Player player, AuthSession s, String code) {
        plugin.async(() -> {
            Optional<Account> opt = auth.findAccount(player.getName());
            if (opt.isEmpty() || opt.get().getTotpSecret() == null) {
                plugin.sync(player, () -> plugin.messages().send(player, "twofa.not-enabled"));
                return;
            }
            if (!TotpUtil.verify(opt.get().getTotpSecret(), code)) {
                plugin.sync(player, () -> plugin.messages().send(player, "twofa.bad-code"));
                return;
            }
            auth.complete2faLogin(player, s);
        });
    }
}
