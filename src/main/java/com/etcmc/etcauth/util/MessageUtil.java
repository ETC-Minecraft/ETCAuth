package com.etcmc.etcauth.util;

import com.etcmc.etcauth.ETCAuth;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Loads and resolves messages from {@code messages.yml} with MiniMessage.
 */
public final class MessageUtil {

    private final ETCAuth plugin;
    private final MiniMessage mm = MiniMessage.miniMessage();
    private FileConfiguration messages;
    private String prefix;

    public MessageUtil(ETCAuth plugin) {
        this.plugin = plugin;
        reload();
    }

    public void reload() {
        File file = new File(plugin.getDataFolder(), "messages.yml");
        if (!file.exists()) plugin.saveResource("messages.yml", false);
        messages = YamlConfiguration.loadConfiguration(file);

        // Merge defaults from JAR
        try (var in = plugin.getResource("messages.yml")) {
            if (in != null) {
                YamlConfiguration defaults = YamlConfiguration.loadConfiguration(
                    new InputStreamReader(in, StandardCharsets.UTF_8));
                messages.setDefaults(defaults);
            }
        } catch (IOException ignored) { /* nothing */ }

        prefix = plugin.getConfig().getString(
            "messages.prefix",
            "<dark_gray>[<gradient:#ffaa00:#ff5555>ETCAuth</gradient>]</dark_gray> ");
    }

    public String raw(String path) {
        return messages.getString(path, "<red>missing-message:" + path);
    }

    public Component get(String path, Map<String, String> placeholders) {
        String text = raw(path);
        if (placeholders != null) {
            for (var e : placeholders.entrySet()) {
                text = text.replace("{" + e.getKey() + "}", e.getValue());
            }
        }
        return mm.deserialize(prefix + text);
    }

    public Component get(String path) {
        return get(path, null);
    }

    public void send(CommandSender to, String path) {
        to.sendMessage(get(path));
    }

    public void send(CommandSender to, String path, Map<String, String> placeholders) {
        to.sendMessage(get(path, placeholders));
    }

    /** Plain (kick) string with placeholders, no MiniMessage prefix. */
    public Component kickMessage(String path, Map<String, String> placeholders) {
        String text = raw(path);
        if (placeholders != null) {
            for (var e : placeholders.entrySet()) {
                text = text.replace("{" + e.getKey() + "}", e.getValue());
            }
        }
        return mm.deserialize(text);
    }
}
