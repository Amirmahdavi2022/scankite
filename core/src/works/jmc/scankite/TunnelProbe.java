/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;

/**
 * Asks an endpoint to fetch something, and checks that the thing came back.
 *
 * <p>This exists because the cheaper tests lie. A TCP connect proves a socket opened, which
 * happens against a black hole. A TLS handshake proves the CDN answered, which it does for every
 * address it owns whether or not your config is behind it. Even the WebSocket upgrade only proves
 * the request reached an origin. None of that is the same as traffic getting through, and the
 * gap between them is exactly where a filtered connection lives: the handshake completes and then
 * nothing comes back.
 *
 * <p>So the last step speaks the actual proxy protocol and asks for a real page over it. If the
 * reply arrives, the config works. There is no cheaper way to know that.
 */
public final class TunnelProbe {

    /**
     * What we ask the endpoint to fetch.
     *
     * <p>Deliberately not a Cloudflare address. A large share of every public pool is served by
     * Cloudflare Workers, and a Worker cannot open a connection to a Cloudflare address at all —
     * so probing through one with a Cloudflare target fails every healthy Worker-backed endpoint
     * and files it as dead.
     */
    public static final String TARGET_HOST = "www.gstatic.com";
    public static final int TARGET_PORT = 80;
    private static String request(boolean last) {
        return "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n"
                + "User-Agent: Mozilla/5.0\r\nConnection: "
                + (last ? "close" : "keep-alive") + "\r\n\r\n";
    }

    /** How far a probe got, which is the only thing that separates the failure modes. */
    public enum Stage {
        /** Nothing answered at the address. */
        NO_SOCKET,
        /** The CDN answered, but the config's own origin did not accept the upgrade. */
        NO_UPGRADE,
        /** The tunnel opened and then carried nothing. This is what interference looks like. */
        NO_TRAFFIC,
        /** A real reply came back through the endpoint. */
        WORKING,
    }

    public static final class Result {
        public final Stage stage;
        public final long millis;
        public final String detail;

        Result(Stage stage, long millis, String detail) {
            this.stage = stage;
            this.millis = millis;
            this.detail = detail == null ? "" : detail;
        }

        public boolean working() { return stage == Stage.WORKING; }

        @Override public String toString() {
            return stage + " in " + millis + "ms" + (detail.isEmpty() ? "" : " (" + detail + ")");
        }
    }

    /** Whether this probe knows how to speak a config's protocol well enough to prove it. */
    public static boolean canProve(ProxyConfig config) {
        return config != null
                && ("vless".equals(config.protocol) || "trojan".equals(config.protocol))
                && !config.transport().isEmpty()
                && ("ws".equals(config.transport()) || "httpupgrade".equals(config.transport()));
    }

    /**
     * Runs the whole exchange over an already-connected stream pair. The caller owns the socket
     * and the TLS, which keeps every byte of this testable against a stub.
     */
    public static Result run(ProxyConfig config, String sni, String host, InputStream in,
                             OutputStream out, Random random) {
        long started = System.currentTimeMillis();
        try {
            // The Host header is the routing name at the far end, and it is not always the same
            // as the name in the certificate. Passing the wrong one here would make the probe
            // disagree with the config it is meant to be testing.
            Ws ws = Ws.open(in, out, host.isEmpty() ? sni : host, config.get("path"), random);

            byte[] header = "trojan".equals(config.protocol)
                    ? trojanHeader(config.id)
                    : vlessHeader(config.id);
            ByteArrayOutputStream first = new ByteArrayOutputStream();
            first.write(header);
            first.write(request(false).getBytes(StandardCharsets.ISO_8859_1));
            ws.send(first.toByteArray());

            String reply = readReply(ws, "vless".equals(config.protocol));
            if (reply == null || !reply.startsWith("HTTP/1")) {
                return new Result(Stage.NO_TRAFFIC, System.currentTimeMillis() - started,
                        reply == null ? "tunnel opened, nothing came back" : "not http");
            }

            // A second round trip on the same tunnel, because the first one proves less than it
            // looks. Plenty of these servers accept a connection, answer once and then stall,
            // which in a client reads as a connection that pings and never carries anything.
            // One exchange cannot tell that apart from a healthy endpoint; two can.
            ws.send(request(true).getBytes(StandardCharsets.ISO_8859_1));
            String second = readReply(ws, false);
            if (second == null || !second.startsWith("HTTP/1")) {
                return new Result(Stage.NO_TRAFFIC, System.currentTimeMillis() - started,
                        "answered once and then stalled");
            }
            return new Result(Stage.WORKING, System.currentTimeMillis() - started,
                    second.substring(0, Math.min(15, second.length())).trim());
        } catch (IOException failure) {
            String message = failure.getMessage() == null ? "" : failure.getMessage();
            Stage stage = message.startsWith("no upgrade") ? Stage.NO_UPGRADE : Stage.NO_TRAFFIC;
            return new Result(stage, System.currentTimeMillis() - started, message);
        }
    }

    /** Reads frames until a whole HTTP head has arrived, or the far side gives up. */
    private static String readReply(Ws ws, boolean stripHeader) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        boolean first = true;
        for (int frames = 0; frames < 12; frames++) {
            byte[] payload = ws.receive();
            if (payload == null) break;
            byte[] usable = payload;
            if (first && stripHeader) {
                usable = stripVlessResponse(payload);
                if (usable == null) return null;
            }
            first = false;
            body.write(usable);
            String text = body.toString("ISO-8859-1");
            if (text.contains("\r\n\r\n") || text.length() > 512) return text;
        }
        String text = body.toString("ISO-8859-1");
        return text.isEmpty() ? null : text;
    }

    // ---------------------------------------------------------------- protocols

    /**
     * VLESS request header: version, uuid, addon length, command, port, address.
     * No encryption of its own — the TLS underneath is the whole of its secrecy.
     */
    static byte[] vlessHeader(String uuid) throws IOException {
        byte[] id = uuidBytes(uuid);
        if (id == null) throw new IOException("credential is not a uuid");
        byte[] name = TARGET_HOST.getBytes(StandardCharsets.US_ASCII);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0);                                   // version
        out.write(id);
        out.write(0);                                   // no addons
        out.write(1);                                   // tcp
        out.write((TARGET_PORT >> 8) & 0xff);
        out.write(TARGET_PORT & 0xff);
        out.write(2);                                   // address is a name
        out.write(name.length);
        out.write(name);
        return out.toByteArray();
    }

    /** Drops the two-byte-plus-addons response header, leaving the payload. */
    static byte[] stripVlessResponse(byte[] payload) {
        if (payload.length < 2) return null;
        int addons = payload[1] & 0xff;
        int offset = 2 + addons;
        if (payload.length < offset) return null;
        byte[] rest = new byte[payload.length - offset];
        System.arraycopy(payload, offset, rest, 0, rest.length);
        return rest;
    }

    /** Trojan: the password as a SHA-224 hex digest, then a SOCKS-shaped destination. */
    static byte[] trojanHeader(String password) throws IOException {
        byte[] name = TARGET_HOST.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(hex(sha224(password.getBytes(StandardCharsets.UTF_8)))
                .getBytes(StandardCharsets.US_ASCII));
        out.write('\r'); out.write('\n');
        out.write(1);                                   // connect
        out.write(3);                                   // address is a name
        out.write(name.length);
        out.write(name);
        out.write((TARGET_PORT >> 8) & 0xff);
        out.write(TARGET_PORT & 0xff);
        out.write('\r'); out.write('\n');
        return out.toByteArray();
    }

    static byte[] uuidBytes(String value) {
        if (value == null) return null;
        String hex = value.replace("-", "").trim();
        if (hex.length() != 32) return null;
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) return null;
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

    static byte[] sha224(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-224").digest(input);
        } catch (Exception missing) {
            throw new IllegalStateException("SHA-224 is required by trojan", missing);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) out.append(String.format("%02x", b & 0xff));
        return out.toString();
    }

    private TunnelProbe() { }
}
