/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * One endpoint, parsed out of the URI formats the public pools publish, and — unlike most
 * parsers — able to write itself back out again.
 *
 * <p>Writing back is the whole point of this class. Finding a fast Cloudflare address is
 * worthless on its own: an address is a door, not a room. What makes it useful is being able to
 * take a working set of credentials and put a different address in front of them, which means
 * taking a link apart and rebuilding it without losing anything that mattered.
 *
 * <p>Nothing here touches the network or Android, so all of it runs on a plain JVM.
 */
public final class ProxyConfig {

    /** vless, vmess, trojan, ss, hysteria2, tuic. */
    public final String protocol;
    /** Whatever the link points at — a hostname or a bare address. */
    public final String address;
    public final int port;
    /** UUID or password; whatever this protocol calls its credential. */
    public final String id;
    /** The #name fragment. Cosmetic, and usually somebody's advertising. */
    public final String label;
    public final Map<String, String> params;
    /** The line exactly as it arrived, kept so a config can be exported untouched. */
    public final String raw;

    private ProxyConfig(String protocol, String address, int port, String id, String label,
                        Map<String, String> params, String raw) {
        this.protocol = protocol;
        this.address = address;
        this.port = port;
        this.id = id;
        this.label = label;
        this.params = params;
        this.raw = raw;
    }

    /** What makes two entries the same server, ignoring the label and the address in front. */
    public String key() {
        return protocol + "|" + address.toLowerCase(Locale.US) + "|" + port + "|" + id;
    }

    /** The declared transport: ws, grpc, xhttp, httpupgrade, tcp... empty when unstated. */
    public String transport() {
        String type = get("type");
        if (type.isEmpty()) type = get("headerType");
        return type.toLowerCase(Locale.US);
    }

    public String security() { return get("security").toLowerCase(Locale.US); }

    public boolean isReality() { return "reality".equals(security()); }

    public String get(String name) {
        String value = params.get(name);
        return value == null ? "" : value;
    }

    @Override public String toString() { return protocol + "://" + address + ":" + port; }

    // ---------------------------------------------------------------- parsing

    /**
     * Parses one line, returning null for anything unrecognised instead of throwing. A pool of
     * ten thousand lines always contains junk, and one bad line must never cost the other
     * nine thousand.
     */
    public static ProxyConfig parse(String line) {
        if (line == null) return null;
        String text = line.trim();
        if (text.isEmpty() || text.startsWith("#") || text.startsWith("//")) return null;

        int scheme = text.indexOf("://");
        if (scheme <= 0) return null;
        String protocol = text.substring(0, scheme).toLowerCase(Locale.US);
        String rest = text.substring(scheme + 3);
        if (rest.isEmpty()) return null;

        switch (protocol) {
            case "vless":
            case "trojan":
            case "hysteria2":
            case "hy2":
            case "tuic":
                return parseUserInfo("hy2".equals(protocol) ? "hysteria2" : protocol, rest, text);
            case "vmess":
                return parseVmess(rest, text);
            case "ss":
                return parseShadowsocks(rest, text);
            default:
                return null;
        }
    }

    /** Reads a whole document: plain text, or base64 wrapped, with junk lines tolerated. */
    public static List<ProxyConfig> parseDocument(String body) {
        List<ProxyConfig> out = new ArrayList<>();
        if (body == null || body.trim().isEmpty()) return out;

        String text = body;
        if (text.indexOf("://") < 0) {
            String decoded = base64(text.replaceAll("\\s", ""));
            if (decoded != null && decoded.contains("://")) text = decoded;
        }
        for (String line : text.split("\\r?\\n")) {
            ProxyConfig config = parse(line);
            if (config != null) out.add(config);
        }
        return out;
    }

    /** vless / trojan / hysteria2 / tuic all share credential@host:port?params#label. */
    private static ProxyConfig parseUserInfo(String protocol, String rest, String raw) {
        String label = "";
        int hash = rest.indexOf('#');
        if (hash >= 0) {
            label = decode(rest.substring(hash + 1));
            rest = rest.substring(0, hash);
        }

        Map<String, String> params = new LinkedHashMap<>();
        int question = rest.indexOf('?');
        if (question >= 0) {
            parseQuery(rest.substring(question + 1), params);
            rest = rest.substring(0, question);
        }

        int at = rest.lastIndexOf('@');
        if (at <= 0) return null;
        String id = decode(rest.substring(0, at));
        String hostPort = rest.substring(at + 1);
        if (id.isEmpty() || hostPort.isEmpty()) return null;

        String address;
        int port;
        if (hostPort.startsWith("[")) {              // [2001:db8::1]:443
            int close = hostPort.indexOf(']');
            if (close < 0) return null;
            address = hostPort.substring(1, close);
            port = readPort(hostPort.substring(close + 1));
        } else {
            int colon = hostPort.lastIndexOf(':');
            if (colon <= 0) return null;
            address = hostPort.substring(0, colon);
            port = readPort(hostPort.substring(colon));
        }
        if (address.isEmpty() || port <= 0 || port > 65535) return null;
        return new ProxyConfig(protocol, address, port, id, label, params, raw);
    }

    /**
     * vmess is base64-wrapped flat JSON. It is a tenth of every pool and most of it is
     * ws+tls behind a CDN, so skipping it would throw away a large share of exactly the
     * configs this app can improve.
     */
    private static ProxyConfig parseVmess(String rest, String raw) {
        String json = base64(rest.trim());
        if (json == null) return null;
        Map<String, String> fields = FlatJson.read(json);
        if (fields.isEmpty()) return null;

        String address = fields.getOrDefault("add", "");
        String id = fields.getOrDefault("id", "");
        int port = readPort(":" + fields.getOrDefault("port", ""));
        if (address.isEmpty() || id.isEmpty() || port <= 0 || port > 65535) return null;

        // Presented through the same accessors as everything else, so callers never special-case
        // vmess. The original field names are kept alongside for faithful re-serialisation.
        Map<String, String> params = new LinkedHashMap<>(fields);
        params.put("type", fields.getOrDefault("net", ""));
        params.put("security", fields.getOrDefault("tls", ""));
        params.put("host", fields.getOrDefault("host", ""));
        params.put("path", fields.getOrDefault("path", ""));
        String sni = fields.getOrDefault("sni", "");
        if (sni.isEmpty()) sni = fields.getOrDefault("host", "");
        params.put("sni", sni);
        return new ProxyConfig("vmess", address, port, id, fields.getOrDefault("ps", ""),
                params, raw);
    }

    /** ss:// arrives as base64(method:password)@host:port, or with the whole lot base64'd. */
    private static ProxyConfig parseShadowsocks(String rest, String raw) {
        String label = "";
        int hash = rest.indexOf('#');
        if (hash >= 0) {
            label = decode(rest.substring(hash + 1));
            rest = rest.substring(0, hash);
        }
        Map<String, String> params = new LinkedHashMap<>();
        int question = rest.indexOf('?');
        if (question >= 0) {
            parseQuery(rest.substring(question + 1), params);
            rest = rest.substring(0, question);
        }
        if (rest.indexOf('@') < 0) {
            String decoded = base64(rest);
            if (decoded == null) return null;
            rest = decoded;
        }
        int at = rest.lastIndexOf('@');
        if (at <= 0) return null;
        String credential = rest.substring(0, at);
        // Order matters here. Publishers percent-encode base64 padding, so '=' arrives as '%3D'
        // and the base64 decode fails on it — unwrap that first. And the percent decoder used
        // must leave '+' alone: a URL decoder turns it into a space and silently corrupts a
        // password, giving an endpoint that looks perfectly fine and can never authenticate.
        if (credential.indexOf('%') >= 0) credential = decode(credential);
        if (credential.indexOf(':') < 0) {
            String decoded = base64(credential);
            if (decoded != null) credential = decoded;
        }
        String hostPort = rest.substring(at + 1);
        int colon = hostPort.lastIndexOf(':');
        if (colon <= 0) return null;
        String address = hostPort.substring(0, colon);
        int port = readPort(hostPort.substring(colon));
        if (address.isEmpty() || port <= 0 || port > 65535 || credential.isEmpty()) return null;
        return new ProxyConfig("ss", address, port, credential, label, params, raw);
    }

    // ------------------------------------------------------------ re-serialising

    /** A copy pointed at a different address, with everything else left alone. */
    public ProxyConfig withAddress(String newAddress, int newPort) {
        return new ProxyConfig(protocol, newAddress, newPort, id, label,
                new LinkedHashMap<>(params), raw);
    }

    /** A copy carrying a different name. */
    public ProxyConfig withLabel(String newLabel) {
        return new ProxyConfig(protocol, address, port, id, newLabel == null ? "" : newLabel,
                new LinkedHashMap<>(params), raw);
    }

    /** A copy with one parameter set, or removed when the value is empty. */
    public ProxyConfig withParam(String name, String value) {
        Map<String, String> copy = new LinkedHashMap<>(params);
        if (value == null || value.isEmpty()) copy.remove(name); else copy.put(name, value);
        return new ProxyConfig(protocol, address, port, id, label, copy, raw);
    }

    /** Writes the link back out in the shape the clients read. */
    public String toUri() {
        if ("vmess".equals(protocol)) return vmessUri();
        StringBuilder out = new StringBuilder(protocol).append("://");
        out.append("ss".equals(protocol)
                ? Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(id.getBytes(StandardCharsets.UTF_8))
                : encode(id));
        out.append('@').append(address.indexOf(':') >= 0 ? "[" + address + "]" : address)
           .append(':').append(port);

        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (entry.getValue() == null || entry.getValue().isEmpty()) continue;
            out.append(first ? '?' : '&').append(encode(entry.getKey()))
               .append('=').append(encode(entry.getValue()));
            first = false;
        }
        if (!label.isEmpty()) out.append('#').append(encode(label));
        return out.toString();
    }

    private String vmessUri() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("v", "2");
        fields.put("ps", label);
        fields.put("add", address);
        fields.put("port", String.valueOf(port));
        fields.put("id", id);
        fields.put("aid", get("aid").isEmpty() ? "0" : get("aid"));
        fields.put("scy", get("scy").isEmpty() ? "auto" : get("scy"));
        fields.put("net", transport());
        fields.put("type", get("headerType").isEmpty() ? "none" : get("headerType"));
        fields.put("host", get("host"));
        fields.put("path", get("path"));
        fields.put("tls", security());
        fields.put("sni", get("sni"));
        String alpn = get("alpn");
        if (!alpn.isEmpty()) fields.put("alpn", alpn);
        String fingerprint = get("fp");
        if (!fingerprint.isEmpty()) fields.put("fp", fingerprint);
        String json = FlatJson.write(fields);
        return "vmess://" + Base64.getEncoder()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    // ---------------------------------------------------------------- helpers

    private static void parseQuery(String query, Map<String, String> into) {
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int equals = pair.indexOf('=');
            if (equals < 0) into.put(decode(pair), "");
            else into.put(decode(pair.substring(0, equals)), decode(pair.substring(equals + 1)));
        }
    }

    private static int readPort(String withColon) {
        if (withColon.isEmpty() || withColon.charAt(0) != ':') return -1;
        try {
            return Integer.parseInt(withColon.substring(1).trim());
        } catch (NumberFormatException bad) {
            return -1;
        }
    }

    static String base64(String value) {
        if (value == null || value.isEmpty()) return null;
        String padded = value.replace('-', '+').replace('_', '/');
        int remainder = padded.length() % 4;
        if (remainder == 2) padded += "==";
        else if (remainder == 3) padded += "=";
        else if (remainder == 1) return null;
        try {
            return new String(Base64.getMimeDecoder().decode(padded), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException bad) {
            return null;
        }
    }

    static String decode(String value) {
        if (value.indexOf('%') < 0 && value.indexOf('+') < 0) return value;
        StringBuilder out = new StringBuilder(value.length());
        byte[] buffer = new byte[value.length()];
        int used = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%' && i + 2 < value.length()) {
                int high = Character.digit(value.charAt(i + 1), 16);
                int low = Character.digit(value.charAt(i + 2), 16);
                if (high >= 0 && low >= 0) {
                    buffer[used++] = (byte) ((high << 4) + low);
                    i += 2;
                    continue;
                }
            }
            if (used > 0) {
                out.append(new String(buffer, 0, used, StandardCharsets.UTF_8));
                used = 0;
            }
            out.append(c);
        }
        if (used > 0) out.append(new String(buffer, 0, used, StandardCharsets.UTF_8));
        return out.toString();
    }

    static String encode(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            boolean safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || "-_.~".indexOf(c) >= 0;
            if (safe) out.append(c);
            else out.append('%').append(String.format("%02X", b & 0xff));
        }
        return out.toString();
    }
}
