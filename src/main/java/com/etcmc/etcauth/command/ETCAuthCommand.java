package com.etcmc.etcauth.command;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.database.Account;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.entity.Player;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

public final class ETCAuthCommand implements CommandExecutor, TabCompleter {

    private static final List<String> SUBS =
        List.of("reload", "info", "unregister", "forcelogin", "premiumcheck", "history", "claim");

    private final ETCAuth plugin;
    private final AuthManager auth;

    public ETCAuthCommand(ETCAuth plugin, AuthManager auth) {
        this.plugin = plugin;
        this.auth = auth;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!sender.hasPermission("etcauth.admin")) {
            sender.sendMessage("No permission.");
            return true;
        }
        if (args.length == 0) {
            plugin.messages().send(sender, "admin.usage");
            return true;
        }

        switch (args[0].toLowerCase()) {
            case "reload"        -> handleReload(sender);
            case "info"          -> handleInfo(sender, args);
            case "unregister"    -> handleUnregister(sender, args);
            case "forcelogin"    -> handleForceLogin(sender, args);
            case "premiumcheck"  -> handlePremiumCheck(sender, args);
            case "history"       -> handleHistory(sender, args);
            case "claim"         -> handleClaim(sender, args);
            default              -> plugin.messages().send(sender, "admin.usage");
        }
        return true;
    }

    private void handleReload(CommandSender sender) {
        plugin.reloadConfig();
        plugin.messages().reload();
        plugin.messages().send(sender, "admin.reload");
    }

    private void handleInfo(CommandSender sender, String[] args) {
        if (args.length < 2) { plugin.messages().send(sender, "admin.usage"); return; }
        String name = args[1];
        plugin.async(() -> {
            Optional<Account> opt = auth.findAccount(name);
            plugin.sync(() -> {
                if (opt.isEmpty()) {
                    plugin.messages().send(sender, "admin.not-found",
                        Map.of("player", name));
                    return;
                }
                Account a = opt.get();
                plugin.messages().send(sender, "admin.info-header",
                    Map.of("player", a.getUsername()));
                send(sender, "uuid",        a.getUuid().toString());
                send(sender, "premium",     String.valueOf(a.isPremium()));
                send(sender, "locked",      String.valueOf(a.isLocked()));
                send(sender, "last_ip",     String.valueOf(a.getLastIp()));
                send(sender, "last_login",  String.valueOf(a.getLastLoginEpochMs()));
                send(sender, "created",     String.valueOf(a.getCreatedEpochMs()));
                send(sender, "has_inv_blob", String.valueOf(a.getInventoryBlob() != null));
            });
        });
    }

    private void send(CommandSender sender, String k, String v) {
        plugin.messages().send(sender, "admin.info-line", Map.of("key", k, "value", v));
    }

    private void handleUnregister(CommandSender sender, String[] args) {
        if (args.length < 2) { plugin.messages().send(sender, "admin.usage"); return; }
        String name = args[1];
        plugin.async(() -> {
            boolean ok = auth.unregister(name);
            plugin.sync(() -> {
                if (ok) plugin.messages().send(sender, "admin.unregistered",
                    Map.of("player", name));
                else    plugin.messages().send(sender, "admin.not-found",
                    Map.of("player", name));
            });
        });
    }

    private void handleForceLogin(CommandSender sender, String[] args) {
        if (args.length < 2) { plugin.messages().send(sender, "admin.usage"); return; }
        Player target = plugin.getServer().getPlayer(args[1]);
        if (target == null) {
            plugin.messages().send(sender, "admin.not-found", Map.of("player", args[1]));
            return;
        }
        AuthSession s = auth.getSession(target.getUniqueId());
        if (s == null) return;
        s.setState(s.isPremium()
            ? com.etcmc.etcauth.auth.AuthState.PREMIUM_AUTHENTICATED
            : com.etcmc.etcauth.auth.AuthState.OFFLINE_AUTHENTICATED);
        plugin.messages().send(sender, "admin.forced-login",
            Map.of("player", target.getName()));
    }

    private void handlePremiumCheck(CommandSender sender, String[] args) {
        if (args.length < 2) { plugin.messages().send(sender, "admin.usage"); return; }
        String name = args[1];
        plugin.async(() -> {
            try {
                Optional<UUID> uuid = auth.resolvePremiumUuid(name);
                plugin.sync(() -> {
                    if (uuid.isPresent()) {
                        plugin.messages().send(sender, "admin.premium-check-result",
                            Map.of("player", name, "uuid", uuid.get().toString()));
                    } else {
                        plugin.messages().send(sender, "admin.premium-check-not-premium",
                            Map.of("player", name));
                    }
                });
            } catch (Exception e) {
                plugin.sync(() -> sender.sendMessage("Lookup failed: " + e.getMessage()));
            }
        });
    }

    private void handleHistory(CommandSender sender, String[] args) {
        if (args.length < 2) { plugin.messages().send(sender, "admin.usage"); return; }
        if (plugin.audit() == null) {
            sender.sendMessage("Audit log is disabled.");
            return;
        }
        String name = args[1];
        int limit = args.length > 2 ? parseInt(args[2], 20) : 20;
        plugin.async(() -> {
            var entries = plugin.audit().recent(name, limit);
            plugin.sync(() -> {
                if (entries.isEmpty()) {
                    plugin.messages().send(sender, "admin.not-found", Map.of("player", name));
                    return;
                }
                plugin.messages().send(sender, "admin.info-header", Map.of("player", name));
                java.text.SimpleDateFormat fmt = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                for (var e : entries) {
                    sender.sendMessage(net.kyori.adventure.text.Component.text(
                        " " + fmt.format(new java.util.Date(e.ts())) + " "
                          + e.event() + " ip=" + (e.ip() == null ? "?" : e.ip())
                          + (e.detail() != null ? " (" + e.detail() + ")" : "")));
                }
            });
        });
    }

    private int parseInt(String s, int def) {
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return def; }
    }

    /**
     * Pre-seeds a premium owner record so the native handshake will engage
     * for that name on the very first connection. Resolves the UUID via
     * Mojang and inserts (or upgrades) the account row as premium+locked
     * with no password (premium accounts don't use one).
     */
    private void handleClaim(CommandSender sender, String[] args) {
        if (args.length < 2) { plugin.messages().send(sender, "admin.usage"); return; }
        String name = args[1];
        plugin.async(() -> {
            Optional<UUID> premium;
            try {
                premium = auth.resolvePremiumUuid(name);
            } catch (Exception e) {
                plugin.sync(() -> sender.sendMessage("Mojang lookup failed: " + e.getMessage()));
                return;
            }
            if (premium.isEmpty()) {
                plugin.sync(() -> plugin.messages().send(sender,
                    "admin.premium-check-not-premium", Map.of("player", name)));
                return;
            }
            UUID realUuid = premium.get();
            try {
                Optional<Account> existing = plugin.database().findByUuid(realUuid);
                long now = System.currentTimeMillis();
                Account claimed = new Account(
                    realUuid, name, null, true, false,
                    null, 0L,
                    existing.map(Account::getCreatedEpochMs).orElse(now),
                    null);
                if (existing.isPresent()) {
                    plugin.database().update(claimed);
                } else {
                    plugin.database().insert(claimed);
                }
                plugin.sync(() -> sender.sendMessage(
                    "§aClaimed §e" + name + "§a (§7" + realUuid
                        + "§a) as premium. Native handshake will now engage on join."));
            } catch (Exception e) {
                plugin.sync(() -> sender.sendMessage("§cClaim failed: " + e.getMessage()));
            }
        });
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command cmd, String alias, String[] args) {
        if (!sender.hasPermission("etcauth.admin")) return List.of();
        if (args.length == 1) {
            return SUBS.stream()
                .filter(s -> s.startsWith(args[0].toLowerCase()))
                .collect(Collectors.toList());
        }
        if (args.length == 2 && Arrays.asList("info", "unregister", "forcelogin", "premiumcheck", "history", "claim")
                .contains(args[0].toLowerCase())) {
            return plugin.getServer().getOnlinePlayers().stream()
                .map(Player::getName)
                .filter(n -> n.toLowerCase().startsWith(args[1].toLowerCase()))
                .collect(Collectors.toList());
        }
        return List.of();
    }
}
