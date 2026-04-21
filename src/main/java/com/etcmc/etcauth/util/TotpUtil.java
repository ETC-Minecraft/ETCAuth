package com.etcmc.etcauth.util;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Thin wrapper around the {@code dev.samstevens.totp} library so the
 * rest of the plugin doesn't import it directly.
 */
public final class TotpUtil {

    private static final SecretGenerator SECRETS = new DefaultSecretGenerator();
    private static final TimeProvider TIME = new SystemTimeProvider();
    private static final CodeGenerator GEN = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
    private static final CodeVerifier VERIFIER = build();

    private TotpUtil() {}

    private static CodeVerifier build() {
        DefaultCodeVerifier v = new DefaultCodeVerifier(GEN, TIME);
        v.setAllowedTimePeriodDiscrepancy(1); // accept previous/next 30s window
        return v;
    }

    public static String newSecret() {
        return SECRETS.generate();
    }

    public static boolean verify(String secret, String code) {
        if (secret == null || code == null) return false;
        return VERIFIER.isValidCode(secret, code.trim());
    }

    /**
     * Build a standard {@code otpauth://} URI that any authenticator app
     * (Google Authenticator, Authy, Aegis…) can import via QR or paste.
     */
    public static String otpauthUri(String issuer, String account, String secret) {
        String label = URLEncoder.encode(issuer + ":" + account, StandardCharsets.UTF_8);
        String iss   = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
        return "otpauth://totp/" + label
             + "?secret=" + secret
             + "&issuer=" + iss
             + "&algorithm=SHA1&digits=6&period=30";
    }
}
