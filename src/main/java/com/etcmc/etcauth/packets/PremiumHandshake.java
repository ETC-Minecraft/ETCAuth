package com.etcmc.etcauth.packets;

import com.etcmc.etcauth.ETCAuth;
import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketListenerPriority;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.wrapper.login.client.WrapperLoginClientLoginStart;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Native premium handshake — drives Vanilla/Paper/Folia's own
 * {@code ServerLoginPacketListenerImpl} into the "online" branch even when
 * the server runs with {@code online-mode=false}.
 *
 * <p>How it works:
 * <ol>
 *   <li>PacketEvents intercepts {@code LoginStart} on the Netty thread.</li>
 *   <li>If the username is a known premium account (resolved via Mojang
 *       cache, async-prewarmed), we look up the {@code Connection} from the
 *       channel pipeline, find the {@code ServerLoginPacketListenerImpl}
 *       attached to it, and reflectively:
 *       <ul>
 *         <li>set {@code requestedUsername} to the username,</li>
 *         <li>generate a 4-byte challenge and set {@code challenge},</li>
 *         <li>flip the listener {@code state} to {@code KEY},</li>
 *         <li>send a vanilla {@code ClientboundHelloPacket} containing
 *             our server's real public key.</li>
 *       </ul>
 *       This is exactly what vanilla does when {@code online-mode=true}.</li>
 *   <li>The client responds with {@code EncryptionResponse}. Vanilla's
 *       {@code handleKey()} runs unchanged: it decrypts with
 *       {@link net.minecraft.server.MinecraftServer#getKeyPair()
 *       MinecraftServer.getKeyPair()} (which exists even in offline mode),
 *       computes the server-id SHA-1 hash, calls
 *       {@code sessionserver.mojang.com/session/minecraft/hasJoined}, and
 *       on success sets the verified premium {@code GameProfile} on the
 *       connection.</li>
 *   <li>The {@code AsyncPlayerPreLoginEvent} fires with the real premium
 *       UUID, so {@link com.etcmc.etcauth.listener.PreLoginListener}
 *       recognises the player as premium without further changes.</li>
 * </ol>
 *
 * <p>If reflection fails (NMS layout changed in a future Paper version),
 * the player falls through to vanilla's offline path. Combined with
 * {@code premium.require-online-mode-for-claim: true} this means the worst
 * case is "the player is asked to /register" — never an impersonation.
 */
public final class PremiumHandshake {

    private static final Pattern VALID_NAME = Pattern.compile("^[A-Za-z0-9_]{1,16}$");
    private static final SecureRandom RNG = new SecureRandom();

    /** Name of the Connection handler in the Netty pipeline. */
    private static final String[] CONNECTION_HANDLER_NAMES = {
        "packet_handler", "packet_handler_unprotected"
    };

    private final ETCAuth plugin;

    // NMS classes / members resolved once at startup ----------------------
    private final Class<?> connectionClass;
    private final Class<?> loginListenerClass;
    private final Class<?> stateEnumClass;
    private final Class<?> helloPacketClass;
    private final Constructor<?> helloPacketCtor;
    private final Field listenerField;       // Connection -> PacketListener
    private final Field requestedUsernameField;
    private final Field challengeField;
    private final Field stateField;
    private final Field serverField;
    private final Method sendMethod;          // Connection.send(Packet)
    private final Method getKeyPairMethod;    // MinecraftServer.getKeyPair()
    private final Object stateKeyEnum;        // State.KEY constant

    private final boolean ready;

    // Per-channel suppression so we don't double-handle the same handshake
    private final Map<Channel, Boolean> driven = new ConcurrentHashMap<>();

    public PremiumHandshake(ETCAuth plugin) {
        this.plugin = plugin;
        Class<?> conn = null, listener = null, state = null, hello = null;
        Constructor<?> hctor = null;
        Field listenerF = null, userF = null, challF = null, stateF = null, serverF = null;
        Method sendM = null, kpM = null;
        Object stateKey = null;
        boolean ok = false;
        try {
            conn = Class.forName("net.minecraft.network.Connection");
            listener = Class.forName("net.minecraft.server.network.ServerLoginPacketListenerImpl");
            // Inner enum State
            for (Class<?> inner : listener.getDeclaredClasses()) {
                if (inner.isEnum() && inner.getSimpleName().equals("State")) {
                    state = inner;
                    break;
                }
            }
            hello = Class.forName("net.minecraft.network.protocol.login.ClientboundHelloPacket");
            hctor = findHelloCtor(hello);

            listenerF  = findListenerField(conn);
            userF      = findFieldByNames(listener, "requestedUsername", "username", "name");
            challF     = findFieldByType(listener, byte[].class);
            stateF     = findFieldByType(listener, state);
            serverF    = findFieldByName(listener, "server");

            sendM = findSendMethod(conn);
            Class<?> mcServerCls = serverF.getType();
            kpM = mcServerCls.getMethod("getKeyPair");

            // Locate KEY enum constant
            for (Object c : state.getEnumConstants()) {
                if (((Enum<?>) c).name().equals("KEY")) { stateKey = c; break; }
            }
            ok = stateKey != null && hctor != null;
        } catch (Throwable t) {
            plugin.getLogger().warning("PremiumHandshake reflection unavailable: " + t.getMessage());
        }
        this.connectionClass = conn;
        this.loginListenerClass = listener;
        this.stateEnumClass = state;
        this.helloPacketClass = hello;
        this.helloPacketCtor = hctor;
        this.listenerField = listenerF;
        this.requestedUsernameField = userF;
        this.challengeField = challF;
        this.stateField = stateF;
        this.serverField = serverF;
        this.sendMethod = sendM;
        this.getKeyPairMethod = kpM;
        this.stateKeyEnum = stateKey;
        this.ready = ok;
        if (ready) {
            plugin.getLogger().info("PremiumHandshake: native online-mode bridge ready (" + helloPacketCtor + ").");
        }
    }

    public boolean isReady() { return ready; }

    /** Returns the PacketEvents listener that drives the handshake. */
    public PacketListenerAbstract listener() {
        return new PacketListenerAbstract(PacketListenerPriority.LOWEST) {
            @Override
            public void onPacketReceive(PacketReceiveEvent event) {
                if (event.getPacketType() != PacketType.Login.Client.LOGIN_START) return;
                if (!ready) return;
                if (!plugin.getConfig().getBoolean("premium.native-handshake", true)) return;

                Object channelObj = event.getChannel();
                if (!(channelObj instanceof Channel ch)) return;
                if (driven.putIfAbsent(ch, Boolean.TRUE) != null) return; // already handled

                String username;
                try {
                    username = new WrapperLoginClientLoginStart(event).getUsername();
                } catch (Throwable t) { return; }
                if (username == null || !VALID_NAME.matcher(username).matches()) return;

                // Premium check (uses cached Mojang lookup; blocks at most a few ms).
                Optional<UUID> premium;
                try {
                    premium = plugin.authManager().resolvePremiumUuid(username);
                } catch (Throwable t) {
                    plugin.getLogger().fine("Mojang lookup failed for " + username + ": " + t.getMessage());
                    return;
                }
                if (premium.isEmpty()) return; // unknown name -> let vanilla handle as offline

                // Only force the encryption handshake when our DB already knows
                // the premium owner of this name. Until that owner has joined
                // at least once (and been recorded as premium), the name is
                // free to be claimed by an offline registration. As soon as
                // the real premium owner connects, the existing claim flow in
                // JoinQuitListener locks the offline account.
                boolean ownerKnown;
                try {
                    var acc = plugin.database().findByUuid(premium.get());
                    ownerKnown = acc.isPresent() && acc.get().isPremium();
                } catch (Throwable t) {
                    ownerKnown = false;
                }
                if (!ownerKnown) {
                    driven.remove(channelObj); // allow normal offline path to proceed
                    return;
                }

                // Drive the vanilla listener into the online branch.
                try {
                    driveOnlineBranch(ch, username);
                    // Cancel: we've already sent the EncryptionRequest. We don't
                    // want vanilla's offline-mode handler to also process the
                    // LoginStart and short-circuit to "ready/offline".
                    event.setCancelled(true);
                } catch (Throwable t) {
                    plugin.getLogger().warning("Native handshake failed for " + username
                        + " — falling back to offline path: " + t.getMessage());
                    driven.remove(ch);
                }
            }
        };
    }

    // -----------------------------------------------------------------
    // Reflection plumbing
    // -----------------------------------------------------------------

    private void driveOnlineBranch(Channel channel, String username) throws Exception {
        Object connection = findConnection(channel);
        if (connection == null) throw new IllegalStateException("Connection handler not in pipeline");
        Object listener = listenerField.get(connection);
        if (!loginListenerClass.isInstance(listener))
            throw new IllegalStateException("Pipeline not in login state (got " + listener + ")");

        Object server = serverField.get(listener);
        java.security.KeyPair keyPair = (java.security.KeyPair) getKeyPairMethod.invoke(server);
        if (keyPair == null) throw new IllegalStateException("Server keypair not available");

        byte[] challenge = new byte[4];
        RNG.nextBytes(challenge);

        // Mutate listener state to KEY (mirrors vanilla handleHello() online branch)
        if (requestedUsernameField != null) {
            try { requestedUsernameField.set(listener, username); } catch (Exception ignored) { }
        }
        challengeField.set(listener, challenge);
        stateField.set(listener, stateKeyEnum);

        Object packet = newHelloPacket(keyPair.getPublic().getEncoded(), challenge);
        sendMethod.invoke(connection, packet);
    }

    private Object findConnection(Channel ch) {
        for (String name : CONNECTION_HANDLER_NAMES) {
            ChannelHandler h = ch.pipeline().get(name);
            if (h != null && connectionClass.isInstance(h)) return h;
        }
        // Last-ditch: scan
        for (Map.Entry<String, ChannelHandler> e : ch.pipeline().toMap().entrySet()) {
            if (connectionClass.isInstance(e.getValue())) return e.getValue();
        }
        return null;
    }

    private Object newHelloPacket(byte[] publicKey, byte[] challenge) throws Exception {
        Class<?>[] params = helloPacketCtor.getParameterTypes();
        // Most common: (String, byte[], byte[], boolean)  — Paper 1.20.5+
        // Older variants: (String, byte[], byte[])
        Object[] args = new Object[params.length];
        int byteSlot = 0;
        for (int i = 0; i < params.length; i++) {
            Class<?> t = params[i];
            if (t == String.class)         args[i] = "";
            else if (t == byte[].class)    args[i] = byteSlot++ == 0 ? publicKey : challenge;
            else if (t == boolean.class)   args[i] = Boolean.TRUE; // shouldAuthenticate
            else throw new IllegalStateException("Unknown ClientboundHelloPacket arg type " + t);
        }
        return helloPacketCtor.newInstance(args);
    }

    private static Constructor<?> findHelloCtor(Class<?> hello) {
        Constructor<?> best = null;
        for (Constructor<?> c : hello.getDeclaredConstructors()) {
            Class<?>[] p = c.getParameterTypes();
            // Need: String + 2x byte[]  (+ optional boolean)
            int strs = 0, bytes = 0, bools = 0, others = 0;
            for (Class<?> t : p) {
                if (t == String.class) strs++;
                else if (t == byte[].class) bytes++;
                else if (t == boolean.class) bools++;
                else others++;
            }
            if (others == 0 && strs == 1 && bytes == 2 && bools <= 1) {
                c.setAccessible(true);
                if (best == null || p.length > best.getParameterCount()) best = c; // prefer the (String, byte[], byte[], boolean) form
            }
        }
        return best;
    }

    private static Field findListenerField(Class<?> conn) throws NoSuchFieldException {
        // Prefer known mojang-mapped name first.
        for (String n : new String[]{"packetListener", "listener", "e"}) {
            try {
                Field f = conn.getDeclaredField(n);
                if (!java.lang.reflect.Modifier.isStatic(f.getModifiers())
                    && !f.getType().getName().contains("Logger")) {
                    f.setAccessible(true);
                    return f;
                }
            } catch (NoSuchFieldException ignored) { }
        }
        Class<?> packetListenerIface;
        try {
            packetListenerIface = Class.forName("net.minecraft.network.PacketListener");
        } catch (ClassNotFoundException e) {
            throw new NoSuchFieldException("PacketListener interface not found");
        }
        for (Field f : conn.getDeclaredFields()) {
            if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
            if (packetListenerIface.isAssignableFrom(f.getType())) {
                f.setAccessible(true);
                return f;
            }
        }
        throw new NoSuchFieldException("packet listener field on " + conn.getName());
    }

    private static Field findField(Class<?> conn, Class<?>... acceptableTypes) throws NoSuchFieldException {
        for (Field f : conn.getDeclaredFields()) {
            if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
            for (Class<?> t : acceptableTypes) {
                if (t != null && t.isAssignableFrom(f.getType())) {
                    f.setAccessible(true); return f;
                }
            }
        }
        throw new NoSuchFieldException("packet listener field on " + conn.getName());
    }

    private static Field findFieldByName(Class<?> owner, String name) throws NoSuchFieldException {
        Field f = owner.getDeclaredField(name);
        f.setAccessible(true);
        return f;
    }

    private static Field findFieldByNames(Class<?> owner, String... names) {
        for (String n : names) {
            try {
                Field f = owner.getDeclaredField(n);
                if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                f.setAccessible(true);
                return f;
            } catch (NoSuchFieldException ignored) { }
        }
        return null;
    }

    private static Field findFieldByType(Class<?> owner, Class<?> type) throws NoSuchFieldException {
        for (Field f : owner.getDeclaredFields()) {
            if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
            if (f.getType() == type) {
                f.setAccessible(true);
                return f;
            }
        }
        throw new NoSuchFieldException("field of type " + type.getName() + " on " + owner.getName());
    }

    private static Method findSendMethod(Class<?> conn) {
        Method best = null;
        for (Method m : conn.getMethods()) {
            if (!m.getName().equals("send")) continue;
            if (m.getParameterCount() != 1) continue;
            // Prefer the single-arg send(Packet)
            if (best == null) best = m;
        }
        if (best != null) best.setAccessible(true);
        return best;
    }
}
