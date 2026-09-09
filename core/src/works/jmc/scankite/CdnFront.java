/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.util.Locale;

/**
 * Decides whether an endpoint sits behind a CDN, and if so puts a different address in front of it.
 *
 * <p>This is the idea the whole app rests on. A config that reaches its server through Cloudflare
 * does not care <em>which</em> Cloudflare address it enters by: the routing is done by the
 * hostname in the TLS handshake and the Host header, not by the address dialled. So the address is
 * a free variable, and on a network where the published one is blocked or slow, another one may
 * not be.
 *
 * <p>The rest of the config is untouchable and stays exactly as published. We are changing the
 * door, not the key.
 *
 * <p>Two families are deliberately excluded. REALITY pins the connection to the real server's own
 * certificate, so there is no CDN in the path to swap. Hysteria2 and TUIC ride on QUIC, and
 * Cloudflare does not carry UDP for ordinary customers.
 */
public final class CdnFront {

    /** TLS ports Cloudflare answers on. The plaintext ones are left out on purpose. */
    public static final int[] TLS_PORTS = { 443, 2053, 2083, 2087, 2096, 8443 };

    private CdnFront() { }

    /** Whether this endpoint's address can be exchanged for a CDN address. */
    public static boolean frontable(ProxyConfig config) {
        if (config == null) return false;
        if (!"vless".equals(config.protocol) && !"vmess".equals(config.protocol)
                && !"trojan".equals(config.protocol)) {
            return false;
        }
        if (config.isReality()) return false;
        if (!"tls".equals(config.security())) return false;

        String transport = config.transport();
        if (!"ws".equals(transport) && !"httpupgrade".equals(transport)
                && !"xhttp".equals(transport) && !"splithttp".equals(transport)
                && !"grpc".equals(transport)) {
            return false;
        }
        return !hostname(config).isEmpty();
    }

    /**
     * The name the connection is really addressed to. This is what has to survive the swap: it
     * travels as the SNI and as the Host header, and it is the only thing that tells the CDN
     * which customer's traffic this is.
     */
    public static String hostname(ProxyConfig config) {
        String sni = config.get("sni").trim();
        if (isHostname(sni)) return sni;
        String host = config.get("host").trim();
        if (host.indexOf(',') > 0) host = host.substring(0, host.indexOf(',')).trim();
        if (isHostname(host)) return host;
        if (isHostname(config.address)) return config.address;
        return "";
    }

    /**
     * The same endpoint entered through {@code edge}.
     *
     * <p>The subtle part: plenty of published configs carry no {@code sni} or {@code host} at all,
     * because the address <em>was</em> the hostname and the client filled both in from it. The
     * moment a bare address goes in the front, that implicit information is gone and the
     * connection lands on a CDN edge that has no idea where to send it. So both are written out
     * explicitly here, whether or not they were there before.
     */
    public static ProxyConfig front(ProxyConfig config, String edge, int port) {
        // Whatever the link stated is kept exactly. Only the ones it left out get filled in, and
        // they are filled from the ORIGINAL ADDRESS, which is what the client would have used.
        //
        // These two are not interchangeable and cross-filling them breaks the config in the
        // quietest possible way. A quarter of the frontable entries in a real pool set them to
        // different values: sni picks the certificate, host picks the route at the far end. Copy
        // one over the other and the handshake still succeeds, the origin still answers the
        // upgrade, and then nothing is ever routed — a connection that pings and carries nothing.
        return config.withAddress(edge, port)
                     .withParam("sni", sniOf(config))
                     .withParam("host", hostOf(config));
    }

    /** The name the certificate must match. */
    public static String sniOf(ProxyConfig config) {
        String sni = config.get("sni").trim();
        return sni.isEmpty() ? implicit(config) : sni;
    }

    /** The name the far end routes on, which grpc does not carry at all. */
    public static String hostOf(ProxyConfig config) {
        if ("grpc".equals(config.transport())) return config.get("host").trim();
        String host = config.get("host").trim();
        if (host.indexOf(',') > 0) host = host.substring(0, host.indexOf(',')).trim();
        return host.isEmpty() ? implicit(config) : host;
    }

    /** What the client would have used when the link named neither: the address itself. */
    private static String implicit(ProxyConfig config) {
        return isHostname(config.address) ? config.address : "";
    }

    /** Whether an address is a name rather than a literal. Only names can front a CDN. */
    public static boolean isHostname(String value) {
        if (value == null) return false;
        String text = value.trim();
        if (text.isEmpty() || text.indexOf(':') >= 0) return false;   // empty, or an IPv6 literal
        if (text.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return false;   // an IPv4 literal
        return text.indexOf('.') > 0 && text.matches("[A-Za-z0-9._\\-]+");
    }

    /** Whether a port is one Cloudflare terminates TLS on. */
    public static boolean isTlsPort(int port) {
        for (int candidate : TLS_PORTS) if (candidate == port) return true;
        return false;
    }

    /**
     * The port to enter on. Keeping the published port matters when it is already a CDN TLS port,
     * because a network that blocks 443 sometimes leaves the alternates alone; anything else has
     * no meaning on a CDN edge and becomes 443.
     */
    public static int entryPort(ProxyConfig config) {
        return isTlsPort(config.port) ? config.port : 443;
    }

    /** A short description of why an endpoint was left alone, for the log. */
    public static String reason(ProxyConfig config) {
        if (config == null) return "unparsed";
        if (config.isReality()) return "reality pins the real server";
        if (!"tls".equals(config.security())) return "no tls to carry a hostname";
        String protocol = config.protocol.toLowerCase(Locale.US);
        if ("hysteria2".equals(protocol) || "tuic".equals(protocol)) return "quic, not carried";
        if ("ss".equals(protocol)) return "no hostname in the protocol";
        if (hostname(config).isEmpty()) return "addressed by ip, no hostname";
        return "transport " + config.transport() + " is not cdn traffic";
    }
}
