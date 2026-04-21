package com.etcmc.etcauth.recovery;

import com.etcmc.etcauth.ETCAuth;
import jakarta.mail.Message;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

import java.security.SecureRandom;
import java.util.Properties;

/**
 * Sends recovery emails using SMTP via Jakarta Mail (shaded). The plugin
 * never logs the SMTP password and never blocks the main thread —
 * callers must invoke {@link #send(String, String, String)} from an
 * async task.
 */
public final class EmailService {

    private static final SecureRandom RNG = new SecureRandom();

    private final ETCAuth plugin;

    public EmailService(ETCAuth plugin) {
        this.plugin = plugin;
    }

    public boolean enabled() {
        return plugin.getConfig().getBoolean("email.enabled", false)
            && !plugin.getConfig().getString("email.host", "").isBlank()
            && !plugin.getConfig().getString("email.from", "").isBlank();
    }

    /** @return a base64url token suitable for inclusion in a URL or chat message. */
    public static String newToken() {
        byte[] bytes = new byte[24];
        RNG.nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Send a single email. Returns {@code true} on success. */
    public boolean send(String to, String subject, String body) {
        if (!enabled()) return false;
        Properties props = new Properties();
        String host = plugin.getConfig().getString("email.host");
        int port    = plugin.getConfig().getInt("email.port", 587);
        boolean starttls = plugin.getConfig().getBoolean("email.starttls", true);
        boolean ssl      = plugin.getConfig().getBoolean("email.ssl", false);
        String user      = plugin.getConfig().getString("email.username", "");
        String pass      = plugin.getConfig().getString("email.password", "");
        String from      = plugin.getConfig().getString("email.from");

        props.put("mail.smtp.host", host);
        props.put("mail.smtp.port", String.valueOf(port));
        props.put("mail.smtp.auth", String.valueOf(!user.isEmpty()));
        props.put("mail.smtp.starttls.enable", String.valueOf(starttls));
        if (ssl) {
            props.put("mail.smtp.ssl.enable", "true");
            props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        }

        Session session = user.isEmpty()
            ? Session.getInstance(props)
            : Session.getInstance(props, new jakarta.mail.Authenticator() {
                @Override protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(user, pass);
                }
            });

        try {
            MimeMessage msg = new MimeMessage(session);
            msg.setFrom(new InternetAddress(from));
            msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
            msg.setSubject(subject, "UTF-8");
            msg.setText(body, "UTF-8");
            Transport.send(msg);
            return true;
        } catch (Exception e) {
            plugin.getLogger().warning("Email send failed to " + to + ": " + e.getMessage());
            return false;
        }
    }
}
