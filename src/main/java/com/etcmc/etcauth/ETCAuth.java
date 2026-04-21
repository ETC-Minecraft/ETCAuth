package com.etcmc.etcauth;

import com.etcmc.etcauth.auth.AuthManager;
import com.etcmc.etcauth.auth.PremiumChecker;
import com.etcmc.etcauth.command.ChangePasswordCommand;
import com.etcmc.etcauth.command.ETCAuthCommand;
import com.etcmc.etcauth.command.ForgotPasswordCommand;
import com.etcmc.etcauth.command.LoginCommand;
import com.etcmc.etcauth.command.LogoutCommand;
import com.etcmc.etcauth.command.RegisterCommand;
import com.etcmc.etcauth.command.ResetPasswordCommand;
import com.etcmc.etcauth.command.SetEmailCommand;
import com.etcmc.etcauth.command.TwoFACommand;
import com.etcmc.etcauth.database.AuditLog;
import com.etcmc.etcauth.database.BackupTask;
import com.etcmc.etcauth.database.Database;
import com.etcmc.etcauth.integration.CacheWarmer;
import com.etcmc.etcauth.integration.ETCAuthExpansion;
import com.etcmc.etcauth.integration.ETCCoreBridge;
import com.etcmc.etcauth.integration.Limbo;
import com.etcmc.etcauth.integration.LuckPermsHook;
import com.etcmc.etcauth.integration.SkinManager;
import com.etcmc.etcauth.recovery.EmailService;
import com.etcmc.etcauth.web.HttpServerHook;
import com.etcmc.etcauth.web.Metrics;
import com.etcmc.etcauth.listener.JoinQuitListener;
import com.etcmc.etcauth.listener.PreLoginListener;
import com.etcmc.etcauth.listener.RestrictionListener;
import com.etcmc.etcauth.packets.PacketHook;
import com.etcmc.etcauth.util.MessageUtil;
import com.etcmc.etcauth.util.PasswordHasher;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * ETCAuth — hybrid premium/offline authentication for Folia.
 *
 * <p>Server expectations:
 * <ul>
 *   <li>{@code online-mode=false} in {@code server.properties} so cracked
 *       clients can connect.</li>
 *   <li>This plugin verifies premium clients against Mojang's API and
 *       enforces password authentication for everyone else.</li>
 * </ul>
 */
public final class ETCAuth extends JavaPlugin {

    private static ETCAuth instance;

    private Database database;
    private AuditLog audit;
    private MessageUtil messages;
    private AuthManager authManager;
    private PremiumChecker premiumChecker;
    private LuckPermsHook luckPerms;
    private ETCCoreBridge etcCoreBridge;
    private Limbo limbo;
    private SkinManager skinManager;
    private EmailService emailService;
    private Metrics metrics;
    private HttpServerHook httpServer;
    private PasswordHasher hasher;

    @Override
    public void onEnable() {
        instance = this;

        saveDefaultConfig();
        // messages.yml is also saved on first run by MessageUtil.
        messages = new MessageUtil(this);

        // ---- DB ----
        database = new Database(this);
        try {
            database.connect();
        } catch (Exception e) {
            getLogger().severe("Could not initialise database: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        if (getConfig().getBoolean("audit.enabled", true)) {
            audit = new AuditLog(this, database);
            audit.install();
        }

        // ---- Auth core ----
        premiumChecker = new PremiumChecker(
            getConfig().getLong("premium.api-timeout-ms", 4000),
            getConfig().getLong("premium.cache-minutes", 60));
        PasswordHasher hasher = new PasswordHasher(
            getConfig().getInt("auth.bcrypt-cost", 11),
            getConfig().getString("auth.password-pepper", ""));
        this.hasher = hasher;
        authManager = new AuthManager(this, database, premiumChecker, hasher);

        // ---- Optional integrations ----
        luckPerms     = new LuckPermsHook(this);
        etcCoreBridge = new ETCCoreBridge(this);
        limbo         = new Limbo(this);
        skinManager   = new SkinManager(this, database);
        emailService  = new EmailService(this);
        metrics       = new Metrics();
        httpServer    = new HttpServerHook(this, metrics);
        httpServer.start();

        if (getServer().getPluginManager().getPlugin("PlaceholderAPI") != null) {
            try {
                new ETCAuthExpansion(this).register();
                getLogger().info("PlaceholderAPI expansion registered.");
            } catch (Throwable t) {
                getLogger().warning("PlaceholderAPI registration failed: " + t.getMessage());
            }
        }

        // ---- Listeners ----
        var pm = getServer().getPluginManager();
        pm.registerEvents(new PreLoginListener(this, authManager), this);
        pm.registerEvents(new JoinQuitListener(this, authManager), this);
        pm.registerEvents(new RestrictionListener(this, authManager), this);

        // ---- Commands ----
        bind("register",       new RegisterCommand(this, authManager));
        bind("login",          new LoginCommand(this, authManager));
        bind("logout",         new LogoutCommand(this, authManager));
        bind("changepassword", new ChangePasswordCommand(this, authManager));
        bind("2fa",            new TwoFACommand(this, authManager));
        bind("setemail",       new SetEmailCommand(this, authManager));
        bind("forgotpassword", new ForgotPasswordCommand(this, authManager, emailService));
        bind("resetpassword",  new ResetPasswordCommand(this, authManager, hasher));

        ETCAuthCommand admin = new ETCAuthCommand(this, authManager);
        var adminCmd = getCommand("etcauth");
        if (adminCmd != null) {
            adminCmd.setExecutor(admin);
            adminCmd.setTabCompleter(admin);
        }

        // Periodic inventory snapshot for currently authenticated players,
        // so that an unexpected crash doesn't lose data the premium owner
        // would inherit on claim. Default: every 5 minutes.
        getServer().getGlobalRegionScheduler().runAtFixedRate(this, t -> {
            for (Player p : getServer().getOnlinePlayers()) {
                async(() -> authManager.persistInventorySnapshot(p));
            }
        }, 6000L, 6000L);

        // Periodic backups (interval-hours from config)
        if (getConfig().getBoolean("backup.enabled", true)) {
            BackupTask backup = new BackupTask(this, database);
            long ticks = BackupTask.intervalTicks(this);
            getServer().getGlobalRegionScheduler().runAtFixedRate(this,
                t -> async(backup), ticks, ticks);
        }

        // Pre-warm Mojang cache for top-N most active accounts
        new CacheWarmer(this).warm();

        // Optional: PacketEvents-based early-handshake protection
        boolean packetEventsPresent = getServer().getPluginManager().getPlugin("packetevents") != null;
        if (packetEventsPresent) {
            try {
                PacketHook.tryEnable(this);
            } catch (Throwable t) {
                getLogger().warning("PacketEvents hook failed to initialize: " + t.getMessage());
            }
        }

        boolean onlineMode = getServer().getOnlineMode();
        boolean nativeHandshakeWanted = getConfig().getBoolean("premium.native-handshake", true);
        boolean nativeHandshakeActive = packetEventsPresent && nativeHandshakeWanted;

        if (!onlineMode && getConfig().getBoolean("premium.enabled", true)
                && !nativeHandshakeActive) {
            getLogger().warning("=================================================================");
            getLogger().warning(" Server is online-mode=false and there is NO trustworthy premium");
            getLogger().warning(" UUID source available:");
            if (!packetEventsPresent) {
                getLogger().warning("   * PacketEvents plugin is NOT installed.");
                getLogger().warning("     Download from: https://github.com/retrooper/packetevents/releases");
                getLogger().warning("     and place packetevents-spigot-x.y.z.jar in plugins/.");
            }
            if (!nativeHandshakeWanted) {
                getLogger().warning("   * premium.native-handshake is set to false in config.yml");
            }
            getLogger().warning(" Without the native handshake, ETCAuth CANNOT cryptographically");
            getLogger().warning(" verify premium ownership. To avoid impersonation, premium");
            getLogger().warning(" auto-claim is being disabled. Every player will need to");
            getLogger().warning(" /register and /login until you install PacketEvents (or run");
            getLogger().warning(" the server in online-mode=true / behind a proxy).");
            getLogger().warning("=================================================================");
            // Hard-disable premium for this run so PreLoginListener takes the
            // safe force-offline branch even if the user left enabled=true.
            getConfig().set("premium.enabled", false);
        }

        getLogger().info("ETCAuth enabled — Folia hybrid authentication active.");
    }

    @Override
    public void onDisable() {
        if (httpServer != null) httpServer.stop();
        if (getServer().getPluginManager().getPlugin("packetevents") != null) {
            try { PacketHook.disable(); } catch (Throwable ignored) {}
        }
        if (authManager != null) authManager.shutdownAll();
        if (database != null)    database.close();
        getLogger().info("ETCAuth disabled.");
    }

    private void bind(String name, org.bukkit.command.CommandExecutor exec) {
        var c = getCommand(name);
        if (c != null) c.setExecutor(exec);
        else getLogger().warning("Command not registered in plugin.yml: " + name);
    }

    // -------------------------------------------------------------------
    // Folia scheduling helpers
    // -------------------------------------------------------------------

    /** Run on a Folia async worker (off the region/main thread). */
    public void async(Runnable r) {
        getServer().getAsyncScheduler().runNow(this, t -> r.run());
    }

    /** Run on the player's owning region (entity scheduler). */
    public void sync(Player target, Runnable r) {
        if (target == null || !target.isOnline()) {
            // Fall back to global region thread
            getServer().getGlobalRegionScheduler().execute(this, r);
            return;
        }
        target.getScheduler().run(this, t -> r.run(), null);
    }

    /** Run on the global region scheduler (no player context). */
    public void sync(Runnable r) {
        getServer().getGlobalRegionScheduler().execute(this, r);
    }

    // -------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------

    public static ETCAuth get()     { return instance; }
    public Database database()      { return database; }
    public AuditLog audit()         { return audit; }
    public MessageUtil messages()   { return messages; }
    public AuthManager authManager(){ return authManager; }
    public PremiumChecker premiumChecker() { return premiumChecker; }
    public LuckPermsHook luckPerms()       { return luckPerms; }
    public ETCCoreBridge etcCoreBridge()   { return etcCoreBridge; }
    public Limbo limbo()                   { return limbo; }
    public SkinManager skinManager()       { return skinManager; }
    public EmailService email()            { return emailService; }
    public Metrics metrics()               { return metrics; }
}
