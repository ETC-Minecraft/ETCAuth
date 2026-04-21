package com.etcmc.etcauth.database;

import com.etcmc.etcauth.ETCAuth;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Optional;
import java.util.UUID;

/**
 * SQLite database wrapper. Single-file persistence under
 * {@code plugins/ETCAuth/<storage.file>}.
 *
 * <p>All writes are serialized through one connection; SQLite handles
 * its own locking. Callers MUST invoke this from off-main threads
 * (use {@link com.etcmc.etcauth.ETCAuth#async}).
 */
public final class Database {

    private final ETCAuth plugin;
    private final File dbFile;
    private Connection connection;

    public Database(ETCAuth plugin) {
        this.plugin = plugin;
        String filename = plugin.getConfig().getString("storage.file", "accounts.db");
        this.dbFile = new File(plugin.getDataFolder(), filename);
    }

    public synchronized void connect() throws SQLException {
        if (connection != null && !connection.isClosed()) return;

        if (!plugin.getDataFolder().exists() && !plugin.getDataFolder().mkdirs()) {
            throw new SQLException("Could not create data folder: " + plugin.getDataFolder());
        }

        // Load the SQLite JDBC driver. We do NOT relocate org.sqlite in
        // the shade plugin because the driver loads native libraries from
        // resources under org/sqlite/native/ which would break under
        // relocation.
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new SQLException("SQLite JDBC driver not found", e);
        }

        connection = DriverManager.getConnection("jdbc:sqlite:" + dbFile.getAbsolutePath());

        try (Statement st = connection.createStatement()) {
            st.execute("PRAGMA journal_mode = WAL");
            st.execute("PRAGMA synchronous = NORMAL");
            st.execute("PRAGMA foreign_keys = ON");
            st.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    uuid               TEXT PRIMARY KEY,
                    username           TEXT NOT NULL COLLATE NOCASE,
                    username_lower     TEXT NOT NULL UNIQUE,
                    password_hash      TEXT,
                    premium            INTEGER NOT NULL DEFAULT 0,
                    locked             INTEGER NOT NULL DEFAULT 0,
                    last_ip            TEXT,
                    last_login_ms      INTEGER NOT NULL DEFAULT 0,
                    created_ms         INTEGER NOT NULL DEFAULT 0,
                    inventory_blob     BLOB,
                    totp_secret        TEXT,
                    skin_value         TEXT,
                    skin_signature     TEXT
                )
            """);
            st.execute("CREATE INDEX IF NOT EXISTS idx_username_lower ON accounts(username_lower)");
            // Idempotent migrations for installs that pre-date Phase 2 columns.
            addColumnIfMissing("accounts", "totp_secret",    "TEXT");
            addColumnIfMissing("accounts", "skin_value",     "TEXT");
            addColumnIfMissing("accounts", "skin_signature", "TEXT");
        }
    }

    private void addColumnIfMissing(String table, String column, String type) throws SQLException {
        try (Statement st = connection.createStatement();
             ResultSet rs = st.executeQuery("PRAGMA table_info(" + table + ")")) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) return;
            }
        }
        try (Statement st = connection.createStatement()) {
            st.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + type);
        }
    }

    public synchronized void close() {
        if (connection == null) return;
        try {
            connection.close();
        } catch (SQLException e) {
            plugin.getLogger().warning("Error closing database: " + e.getMessage());
        } finally {
            connection = null;
        }
    }

    public Connection raw() {
        return connection;
    }

    // -------------------------------------------------------------------
    // CRUD
    // -------------------------------------------------------------------

    public Optional<Account> findByUsername(String username) throws SQLException {
        String sql = "SELECT * FROM accounts WHERE username_lower = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.toLowerCase());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(read(rs)) : Optional.empty();
            }
        }
    }

    public Optional<Account> findByUuid(UUID uuid) throws SQLException {
        String sql = "SELECT * FROM accounts WHERE uuid = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, uuid.toString());
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(read(rs)) : Optional.empty();
            }
        }
    }

    public void insert(Account a) throws SQLException {
        String sql = """
            INSERT INTO accounts
                (uuid, username, username_lower, password_hash, premium,
                 locked, last_ip, last_login_ms, created_ms, inventory_blob,
                 totp_secret, skin_value, skin_signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, a.getUuid().toString());
            ps.setString(2, a.getUsername());
            ps.setString(3, a.getUsername().toLowerCase());
            ps.setString(4, a.getPasswordHash());
            ps.setInt(5, a.isPremium() ? 1 : 0);
            ps.setInt(6, a.isLocked() ? 1 : 0);
            ps.setString(7, a.getLastIp());
            ps.setLong(8, a.getLastLoginEpochMs());
            ps.setLong(9, a.getCreatedEpochMs());
            ps.setBytes(10, a.getInventoryBlob());
            ps.setString(11, a.getTotpSecret());
            ps.setString(12, a.getSkinValue());
            ps.setString(13, a.getSkinSignature());
            ps.executeUpdate();
        }
    }

    public void update(Account a) throws SQLException {
        String sql = """
            UPDATE accounts SET
                username = ?, password_hash = ?, premium = ?, locked = ?,
                last_ip = ?, last_login_ms = ?, inventory_blob = ?,
                totp_secret = ?, skin_value = ?, skin_signature = ?
            WHERE uuid = ?
        """;
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, a.getUsername());
            ps.setString(2, a.getPasswordHash());
            ps.setInt(3, a.isPremium() ? 1 : 0);
            ps.setInt(4, a.isLocked() ? 1 : 0);
            ps.setString(5, a.getLastIp());
            ps.setLong(6, a.getLastLoginEpochMs());
            ps.setBytes(7, a.getInventoryBlob());
            ps.setString(8, a.getTotpSecret());
            ps.setString(9, a.getSkinValue());
            ps.setString(10, a.getSkinSignature());
            ps.setString(11, a.getUuid().toString());
            ps.executeUpdate();
        }
    }

    public void deleteByUsername(String username) throws SQLException {
        String sql = "DELETE FROM accounts WHERE username_lower = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.toLowerCase());
            ps.executeUpdate();
        }
    }

    private Account read(ResultSet rs) throws SQLException {
        return new Account(
            UUID.fromString(rs.getString("uuid")),
            rs.getString("username"),
            rs.getString("password_hash"),
            rs.getInt("premium") == 1,
            rs.getInt("locked") == 1,
            rs.getString("last_ip"),
            rs.getLong("last_login_ms"),
            rs.getLong("created_ms"),
            rs.getBytes("inventory_blob"),
            rs.getString("totp_secret"),
            rs.getString("skin_value"),
            rs.getString("skin_signature")
        );
    }
}
