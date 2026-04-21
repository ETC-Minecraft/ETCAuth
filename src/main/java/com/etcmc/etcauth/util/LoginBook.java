package com.etcmc.etcauth.util;

import com.etcmc.etcauth.ETCAuth;
import com.etcmc.etcauth.auth.AuthSession;
import com.etcmc.etcauth.auth.AuthState;
import net.kyori.adventure.inventory.Book;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;
import org.bukkit.entity.Player;

/**
 * Sends a polished welcome book to non-authenticated players. The book
 * has clickable suggestions ("/login " / "/register ") so the player
 * can simply click and type their password without remembering syntax.
 *
 * <p>Folia-safe: the open-book call runs on the player's region scheduler.
 */
public final class LoginBook {

    private LoginBook() {}

    public static void open(ETCAuth plugin, Player player, AuthSession session) {
        if (!plugin.getConfig().getBoolean("login-book.enabled", true)) return;

        boolean register = session.getState() == AuthState.AWAITING_REGISTER;
        String title = plugin.getConfig().getString("login-book.title", "ETCAuth");
        String author = plugin.getConfig().getString("login-book.author", "ETCMC");

        Component header = Component.text(register ? "Crear cuenta" : "Iniciar sesión",
                NamedTextColor.DARK_RED, TextDecoration.BOLD)
            .appendNewline()
            .append(Component.text("─────────────", NamedTextColor.DARK_GRAY))
            .appendNewline().appendNewline();

        Component body;
        if (register) {
            body = Component.text("¡Bienvenido, ", NamedTextColor.DARK_GRAY)
                .append(Component.text(player.getName(), NamedTextColor.BLACK))
                .append(Component.text("!", NamedTextColor.DARK_GRAY))
                .appendNewline().appendNewline()
                .append(Component.text("Esta cuenta es nueva. Para crearla escribe:",
                    NamedTextColor.DARK_GRAY))
                .appendNewline().appendNewline()
                .append(Component.text("[Click para registrar]", NamedTextColor.BLUE,
                        TextDecoration.UNDERLINED)
                    .clickEvent(ClickEvent.suggestCommand("/register "))
                    .hoverEvent(Component.text("Sugiere /register en el chat")))
                .appendNewline().appendNewline()
                .append(Component.text("Formato: ", NamedTextColor.DARK_GRAY))
                .append(Component.text("/register <pass> <pass>", NamedTextColor.DARK_GREEN));
        } else {
            body = Component.text("Bienvenido de nuevo, ", NamedTextColor.DARK_GRAY)
                .append(Component.text(player.getName(), NamedTextColor.BLACK))
                .append(Component.text(".", NamedTextColor.DARK_GRAY))
                .appendNewline().appendNewline()
                .append(Component.text("[Click para iniciar sesión]", NamedTextColor.BLUE,
                        TextDecoration.UNDERLINED)
                    .clickEvent(ClickEvent.suggestCommand("/login "))
                    .hoverEvent(Component.text("Sugiere /login en el chat")))
                .appendNewline().appendNewline()
                .append(Component.text("Formato: ", NamedTextColor.DARK_GRAY))
                .append(Component.text("/login <pass>", NamedTextColor.DARK_GREEN));
        }

        Component page = header.append(body);
        Book book = Book.book(Component.text(title), Component.text(author), page);

        // Open on the player's region thread (Folia rule).
        player.getScheduler().run(plugin, t -> {
            try {
                player.openBook(book);
            } catch (Throwable ignored) {
                // Some clients (Bedrock via Geyser) can't render virtual books;
                // we already sent the chat prompt as a fallback.
            }
        }, null);
    }
}
