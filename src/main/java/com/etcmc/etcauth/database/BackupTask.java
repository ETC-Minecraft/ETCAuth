package com.etcmc.etcauth.database;

import com.etcmc.etcauth.ETCAuth;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

/**
 * Periodic backup of {@code accounts.db} → {@code backups/accounts-<ts>.db.gz}
 * with rotation (keeps the N most recent files).
 *
 * <p>Designed for a non-busy server: copies the live DB file under SQLite's
 * WAL mode, which is safe because writers always commit through the journal
 * before the main file is mutated.
 */
public final class BackupTask implements Runnable {

    private final ETCAuth plugin;
    private final Database db;
    private final File backupDir;
    private final int keepCount;

    public BackupTask(ETCAuth plugin, Database db) {
        this.plugin = plugin;
        this.db = db;
        this.backupDir = new File(plugin.getDataFolder(), "backups");
        this.keepCount = plugin.getConfig().getInt("backup.keep", 14);
        if (!backupDir.exists()) backupDir.mkdirs();
    }

    public static long intervalTicks(ETCAuth plugin) {
        long hours = plugin.getConfig().getLong("backup.interval-hours", 12);
        return TimeUnit.HOURS.toSeconds(hours) * 20L;
    }

    @Override
    public void run() {
        if (!plugin.getConfig().getBoolean("backup.enabled", true)) return;

        File source = new File(plugin.getDataFolder(),
            plugin.getConfig().getString("storage.file", "accounts.db"));
        if (!source.exists()) return;

        String ts = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
        File dest = new File(backupDir, "accounts-" + ts + ".db.gz");

        try (var in  = Files.newInputStream(source.toPath());
             var out = new GZIPOutputStream(Files.newOutputStream(dest.toPath()))) {
            in.transferTo(out);
            plugin.getLogger().info("[backup] Created " + dest.getName()
                + " (" + (dest.length() / 1024) + " KiB)");
        } catch (Exception e) {
            plugin.getLogger().warning("[backup] Failed: " + e.getMessage());
            return;
        }

        rotate();
    }

    private void rotate() {
        File[] all = backupDir.listFiles((d, n) -> n.startsWith("accounts-") && n.endsWith(".db.gz"));
        if (all == null || all.length <= keepCount) return;

        Arrays.sort(all, Comparator.comparingLong(File::lastModified).reversed());
        for (int i = keepCount; i < all.length; i++) {
            if (all[i].delete()) {
                plugin.getLogger().info("[backup] Pruned old backup " + all[i].getName());
            }
        }
    }
}
