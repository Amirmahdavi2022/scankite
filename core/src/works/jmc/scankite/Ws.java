/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Random;

/**
 * Just enough WebSocket to carry a proxy protocol, written against RFC 6455 rather than a library.
 *
 * <p>Everything a client sends has to be masked, and the mask is per-frame. Servers close the
 * connection on an unmasked frame, so getting this wrong looks like the endpoint rejecting you.
 */
public final class Ws {

    /** RFC 6455's fixed handshake salt. The server hashes the key with it to prove it understood. */
    private static final String SALT = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private final InputStream in;
    private final OutputStream out;
    private final Random random;

    private Ws(InputStream in, OutputStream out, Random random) {
        this.in = in;
        this.out = out;
        this.random = random;
    }

    /**
     * Performs the upgrade and returns a connected channel, or throws with what came back instead.
     *
     * <p>{@code host} is the name the far side routes on, which on a CDN is not the address we
     * dialled — that mismatch is the entire trick and it has to be written out deliberately.
     */
    public static Ws open(InputStream in, OutputStream out, String host, String path,
                          Random random) throws IOException {
        byte[] nonce = new byte[16];
        random.nextBytes(nonce);
        String key = Base64.getEncoder().encodeToString(nonce);

        String request = "GET " + (path == null || path.isEmpty() ? "/" : path) + " HTTP/1.1\r\n"
                + "Host: " + host + "\r\n"
                + "User-Agent: Mozilla/5.0\r\n"
                + "Connection: Upgrade\r\n"
                + "Upgrade: websocket\r\n"
                + "Sec-WebSocket-Version: 13\r\n"
                + "Sec-WebSocket-Key: " + key + "\r\n\r\n";
        out.write(request.getBytes(StandardCharsets.ISO_8859_1));
        out.flush();

        String status = readLine(in);
        if (status == null) throw new IOException("closed before answering");
        if (!status.contains(" 101")) {
            // Worth keeping verbatim: a 400 from the origin and a 5xx page from the CDN mean
            // completely different things, and only one of them is the endpoint's fault.
            throw new IOException("no upgrade: " + status.trim());
        }
        String accept = null;
        String line;
        while ((line = readLine(in)) != null && !line.trim().isEmpty()) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim()
                    .equalsIgnoreCase("Sec-WebSocket-Accept")) {
                accept = line.substring(colon + 1).trim();
            }
        }
        String expected = accept(key);
        if (accept == null || !accept.equals(expected)) {
            throw new IOException("upgrade accepted with the wrong key");
        }
        return new Ws(in, out, random);
    }

    static String accept(String key) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return Base64.getEncoder().encodeToString(
                    sha1.digest((key + SALT).getBytes(StandardCharsets.ISO_8859_1)));
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /** Sends one masked binary frame. */
    public void send(byte[] payload) throws IOException {
        byte[] mask = new byte[4];
        random.nextBytes(mask);

        java.io.ByteArrayOutputStream frame = new java.io.ByteArrayOutputStream();
        frame.write(0x82);                                  // FIN + binary
        int length = payload.length;
        if (length < 126) {
            frame.write(0x80 | length);
        } else if (length < 65536) {
            frame.write(0x80 | 126);
            frame.write((length >> 8) & 0xff);
            frame.write(length & 0xff);
        } else {
            frame.write(0x80 | 127);
            for (int shift = 56; shift >= 0; shift -= 8) frame.write((int) ((long) length >> shift) & 0xff);
        }
        frame.write(mask, 0, 4);
        byte[] masked = new byte[length];
        for (int i = 0; i < length; i++) masked[i] = (byte) (payload[i] ^ mask[i & 3]);
        frame.write(masked, 0, length);

        out.write(frame.toByteArray());
        out.flush();
    }

    /**
     * Reads one data frame's payload. Control frames are handled and skipped; a close frame
     * returns null.
     */
    public byte[] receive() throws IOException {
        while (true) {
            int first = in.read();
            if (first < 0) return null;
            int opcode = first & 0x0f;
            int second = in.read();
            if (second < 0) return null;
            boolean masked = (second & 0x80) != 0;
            long length = second & 0x7f;
            if (length == 126) {
                length = ((long) need() << 8) | need();
            } else if (length == 127) {
                length = 0;
                for (int i = 0; i < 8; i++) length = (length << 8) | need();
            }
            if (length > 1 << 20) throw new IOException("frame far too large");

            byte[] mask = new byte[4];
            if (masked) for (int i = 0; i < 4; i++) mask[i] = (byte) need();

            byte[] payload = new byte[(int) length];
            int read = 0;
            while (read < payload.length) {
                int got = in.read(payload, read, payload.length - read);
                if (got < 0) return null;
                read += got;
            }
            if (masked) for (int i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];

            if (opcode == 0x8) return null;                  // close
            if (opcode == 0x9) { pong(payload); continue; }  // ping
            if (opcode == 0xA) continue;                     // pong
            return payload;
        }
    }

    private void pong(byte[] payload) throws IOException {
        byte[] mask = new byte[4];
        random.nextBytes(mask);
        out.write(0x8A);
        out.write(0x80 | payload.length);
        out.write(mask);
        byte[] masked = new byte[payload.length];
        for (int i = 0; i < payload.length; i++) masked[i] = (byte) (payload[i] ^ mask[i & 3]);
        out.write(masked);
        out.flush();
    }

    private int need() throws IOException {
        int value = in.read();
        if (value < 0) throw new IOException("truncated frame header");
        return value;
    }

    static String readLine(InputStream in) throws IOException {
        StringBuilder line = new StringBuilder();
        int c;
        while ((c = in.read()) >= 0) {
            if (c == '\n') return line.toString();
            if (c != '\r') line.append((char) c);
            if (line.length() > 8192) throw new IOException("header line far too long");
        }
        return line.length() == 0 ? null : line.toString();
    }
}
