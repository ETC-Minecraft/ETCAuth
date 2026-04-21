package com.etcmc.etcauth.database;

import com.etcmc.etcauth.ETCAuth;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Persistent audit trail of authentication events.
 *
 * <p>Inserts are intentionally non-blocking: callers should invoke
 * {@link #log(String, String, String, String)} from an async task; the
 * log is best-effort and a single failed insert never affects auth.
 */
public final class AuditLog {

    public record Entry(long ts, String username, String event, String ip, String detail) {}

    private final ETCAuth plugin;
    private final Database db;

    public AuditLog(ETCAuth plugin, Database db) {
        this.plugin = plugin;
        this.db = db;
    }

    public void install() {
        try (Statement st = db.raw().createStatement()) {
            st.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts        INTEGER NOT NULL,
                    username  TEXT NOT NULL COLLATE NOCASE,
                    event     TEXT NOT NULL,
                    ip        TEXT,
                    detail    TEXT
                )
            """);
            st.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username)");
            st.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts   ON audit_log(ts)");
        } catch (SQLException e) {
            plugin.getLogger().severe("Could not create audit_log table: " + e.getMessage());
        }
    }

    public void log(String username, String event, String ip, String detail) {
        String sql = "INSERT INTO audit_log (ts, username, event, ip, detail) VALUES (?, ?, ?, ?, ?)";
        try (PreparedStatement ps = db.raw().prepareStatement(sql)) {
            ps.setLong(1, System.currentTimeMillis());
            ps.setString(2, username);
            ps.setString(3, event);
            ps.setString(4, ip);
            ps.setString(5, detail);
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().warning("audit_log insert failed: " + e.getMessage());
        }
    }

    public List<Entry> recent(String username, int limit) {
        List<Entry> out = new ArrayList<>();
        String sql = "SELECT ts, username, event, ip, detail FROM audit_log "
                   + "WHERE username = ? COLLATE NOCASE ORDER BY ts DESC LIMIT ?";
        try (PreparedStatement ps = db.raw().prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setInt(2, Math.max(1, Math.min(limit, 200)));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    out.add(new Entry(
                        rs.getLong("ts"),
                        rs.getString("username"),
                        rs.getString("event"),
                        rs.getString("ip"),
                        rs.getString("detail")));
                }
            }
        } catch (SQLException e) {
            plugin.getLogger().warning("audit_log query failed: " + e.getMessage());
        }
        return out;
    }
}
