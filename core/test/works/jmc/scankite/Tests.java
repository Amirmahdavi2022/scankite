/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.util.List;
import java.util.Random;

/** Every check in the core. No framework: {@code java Tests} runs them and exits non-zero on a failure. */
public final class Tests {

    private static int passed;
    private static int failed;

    public static void main(String[] args) {
        parsing();
        vmess();
        roundTrip();
        watermarks();
        fronting();
        ranges();
        sampling();
        exporting();
        tunnelling();

        System.out.println();
        System.out.println(failed == 0
                ? "all " + passed + " checks passed"
                : failed + " of " + (passed + failed) + " checks FAILED");
        if (failed > 0) System.exit(1);
    }

    // ---------------------------------------------------------------- parsing

    static void parsing() {
        ProxyConfig vless = ProxyConfig.parse(
                "vless://11111111-2222-3333-4444-555555555555@example.com:443"
                        + "?encryption=none&security=tls&sni=example.com&type=ws&host=example.com"
                        + "&path=%2Fws%3Fed%3D2560#US%20%7C%20%40somechannel");
        check("vless protocol", "vless", vless.protocol);
        check("vless address", "example.com", vless.address);
        check("vless port", 443, vless.port);
        check("vless credential", "11111111-2222-3333-4444-555555555555", vless.id);
        check("vless transport", "ws", vless.transport());
        check("path is decoded once", "/ws?ed=2560", vless.get("path"));
        check("label is decoded", "US | @somechannel", vless.label);

        ProxyConfig trojan = ProxyConfig.parse("trojan://pass word@1.2.3.4:8443?security=tls#x");
        check("trojan parses", "trojan", trojan.protocol);
        check("trojan literal address", "1.2.3.4", trojan.address);

        ProxyConfig six = ProxyConfig.parse("vless://abc@[2001:db8::1]:443?security=tls#v6");
        check("ipv6 literal unbracketed", "2001:db8::1", six.address);
        check("ipv6 port", 443, six.port);

        check("junk line ignored", null, ProxyConfig.parse("not a config at all"));
        check("comment ignored", null, ProxyConfig.parse("# a heading"));
        check("empty ignored", null, ProxyConfig.parse("   "));
        check("unknown scheme ignored", null, ProxyConfig.parse("ftp://host:21"));
        check("missing credential ignored", null, ProxyConfig.parse("vless://@host:443"));
        check("bad port ignored", null, ProxyConfig.parse("vless://abc@host:99999"));

        // A shadowsocks credential whose base64 padding arrived percent-encoded. Decoding the
        // whole thing with a URL decoder turns base64's '+' into a space and silently corrupts
        // the password, producing an endpoint that looks fine and can never authenticate.
        ProxyConfig ss = ProxyConfig.parse("ss://YWVzLTI1Ni1nY206cGErc3M%3D@1.2.3.4:8388#n");
        check("ss credential survives", "aes-256-gcm:pa+ss", ss.id);

        List<ProxyConfig> document = ProxyConfig.parseDocument(
                "#profile-title: somebody\nvless://a@h1.com:443?security=tls\njunk\n"
                        + "trojan://b@h2.com:443?security=tls\n");
        check("document skips junk and headings", 2, document.size());
    }

    static void vmess() {
        String json = "{\"v\":\"2\",\"ps\":\"@chan | DE\",\"add\":\"cdn.example.com\","
                + "\"port\":\"443\",\"id\":\"aaaa-bbbb\",\"aid\":0,\"net\":\"ws\","
                + "\"host\":\"cdn.example.com\",\"path\":\"/p\",\"tls\":\"tls\"}";
        String uri = "vmess://" + java.util.Base64.getEncoder()
                .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        ProxyConfig config = ProxyConfig.parse(uri);
        check("vmess parses", "vmess", config.protocol);
        check("vmess address", "cdn.example.com", config.address);
        check("vmess port from string field", 443, config.port);
        check("vmess numeric field survives", "aaaa-bbbb", config.id);
        check("vmess transport normalised", "ws", config.transport());
        check("vmess security normalised", "tls", config.security());
        check("vmess sni filled from host", "cdn.example.com", config.get("sni"));
        check("vmess label", "@chan | DE", config.label);

        check("nested json refused", true, FlatJson.read("{\"a\":{\"b\":1}}").isEmpty());
        check("escapes survive", "a\"b", FlatJson.read("{\"k\":\"a\\\"b\"}").get("k"));
        check("null becomes empty", "", FlatJson.read("{\"k\":null}").get("k"));
        check("not json at all", true, FlatJson.read("hello").isEmpty());
    }

    static void roundTrip() {
        String uri = "vless://11111111-2222-3333-4444-555555555555@example.com:443"
                + "?encryption=none&security=tls&sni=example.com&type=ws&host=example.com"
                + "&path=%2Fws%3Fed%3D2560#name";
        ProxyConfig once = ProxyConfig.parse(uri);
        ProxyConfig twice = ProxyConfig.parse(once.toUri());
        check("round trip keeps address", once.address, twice.address);
        check("round trip keeps credential", once.id, twice.id);
        check("round trip keeps path", once.get("path"), twice.get("path"));
        check("round trip keeps label", once.label, twice.label);
        check("round trip is stable", once.toUri(), twice.toUri());

        // The path is the one that bites: it contains its own ? and =, so an encoder that lets
        // those through produces a link the client reads as extra parameters.
        check("path stays encoded in output", true, once.toUri().contains("%2Fws%3Fed%3D2560"));

        ProxyConfig vmessOnce = ProxyConfig.parse(ProxyConfig.parse(
                "vmess://" + java.util.Base64.getEncoder().encodeToString(
                        ("{\"v\":\"2\",\"ps\":\"n\",\"add\":\"a.com\",\"port\":\"443\","
                                + "\"id\":\"x\",\"net\":\"ws\",\"host\":\"a.com\",\"path\":\"/q\","
                                + "\"tls\":\"tls\"}")
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8))).toUri());
        check("vmess round trip address", "a.com", vmessOnce.address);
        check("vmess round trip path", "/q", vmessOnce.get("path"));

        ProxyConfig ss = ProxyConfig.parse("ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#n");
        check("ss round trip", "aes-256-gcm:pass", ProxyConfig.parse(ss.toUri()).id);
    }

    // ---------------------------------------------------------------- watermarks

    static void watermarks() {
        check("handle removed", "US 🇺🇸 6F42E7",
                Watermark.strip("US 🇺🇸 | @Raydikalx | 6F42E7"));
        check("telegram link removed", "DE", Watermark.strip("DE | t.me/somechannel"));
        check("url removed", "NL", Watermark.strip("NL | https://example.com/join"));
        check("channel-shaped word removed", "FR", Watermark.strip("FR | v2ray_phoenix"));
        check("brand-only label empties", "", Watermark.strip("@NapsterNetvIrani"));
        check("plain label untouched", "Frankfurt 03", Watermark.strip("Frankfurt 03"));
        check("empty stays empty", "", Watermark.strip(""));
        check("null stays empty", "", Watermark.strip(null));

        // A short generic word on its own is not a watermark. Stripping it would throw away a
        // legitimate name for the sake of a pattern.
        check("bare word kept", "net", Watermark.strip("net"));

        check("brands reported", 1, Watermark.brands("US | @Raydikalx | 6F42E7").size());
        check("brand text reported", "@Raydikalx",
                Watermark.brands("US | @Raydikalx | 6F42E7").get(0));
        check("no brands to report", 0, Watermark.brands("Frankfurt 03").size());

        check("profile-title is a directive", true,
                Watermark.isDirective("#profile-title: @Raydikalx — TOP 100"));
        check("support-url is a directive", true,
                Watermark.isDirective("#support-url: https://t.me/x"));
        check("ordinary comment is not", false, Watermark.isDirective("# sorted by delay"));
        check("config line is not", false,
                Watermark.isDirective("vless://a@b.com:443"));

        check("own tag applied", "JMC 7", Watermark.rename("JMC", 7));
        check("no tag means no name", "", Watermark.rename("", 7));
        check("blank tag means no name", "", Watermark.rename("   ", 7));
    }

    // ---------------------------------------------------------------- fronting

    static void fronting() {
        ProxyConfig ws = ProxyConfig.parse(
                "vless://uuid@cdn.example.com:443?security=tls&type=ws&host=cdn.example.com"
                        + "&path=%2Fp#n");
        check("ws+tls is frontable", true, CdnFront.frontable(ws));
        check("hostname found", "cdn.example.com", CdnFront.hostname(ws));

        ProxyConfig reality = ProxyConfig.parse(
                "vless://uuid@1.2.3.4:443?security=reality&type=tcp&sni=microsoft.com&pbk=k#n");
        check("reality is not frontable", false, CdnFront.frontable(reality));
        check("reality reason", "reality pins the real server", CdnFront.reason(reality));

        ProxyConfig quic = ProxyConfig.parse("hysteria2://pw@1.2.3.4:443?sni=a.com#n");
        check("quic is not frontable", false, CdnFront.frontable(quic));

        ProxyConfig plain = ProxyConfig.parse("vless://uuid@1.2.3.4:80?type=ws&host=a.com#n");
        check("no tls is not frontable", false, CdnFront.frontable(plain));

        ProxyConfig bare = ProxyConfig.parse("vless://uuid@1.2.3.4:443?security=tls&type=ws#n");
        check("no hostname anywhere is not frontable", false, CdnFront.frontable(bare));
        check("bare reason", "addressed by ip, no hostname", CdnFront.reason(bare));

        // The important one. This config names its host only by its address, so both sni and host
        // are implicit. Put a bare address in front without writing them out and the edge has
        // nothing to route on.
        ProxyConfig implicit = ProxyConfig.parse(
                "vless://uuid@cdn.example.com:443?security=tls&type=ws&path=%2Fp#n");
        check("implicit hostname is frontable", true, CdnFront.frontable(implicit));
        ProxyConfig fronted = CdnFront.front(implicit, "104.16.5.9", 443);
        check("address swapped", "104.16.5.9", fronted.address);
        check("sni made explicit", "cdn.example.com", fronted.get("sni"));
        check("host made explicit", "cdn.example.com", fronted.get("host"));
        check("credential untouched", implicit.id, fronted.id);
        check("path untouched", "/p", fronted.get("path"));
        check("fronted link reparses", "104.16.5.9",
                ProxyConfig.parse(fronted.toUri()).address);

        ProxyConfig frontedVmess = CdnFront.front(ProxyConfig.parse(
                "vmess://" + java.util.Base64.getEncoder().encodeToString(
                        ("{\"v\":\"2\",\"ps\":\"n\",\"add\":\"c.example.com\",\"port\":\"443\","
                                + "\"id\":\"x\",\"net\":\"ws\",\"path\":\"/q\",\"tls\":\"tls\"}")
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8))),
                "104.16.5.9", 2053);
        ProxyConfig reread = ProxyConfig.parse(frontedVmess.toUri());
        check("vmess address swapped", "104.16.5.9", reread.address);
        check("vmess port swapped", 2053, reread.port);
        check("vmess host preserved", "c.example.com", reread.get("host"));

        check("443 is a tls port", true, CdnFront.isTlsPort(443));
        check("2053 is a tls port", true, CdnFront.isTlsPort(2053));
        check("80 is not", false, CdnFront.isTlsPort(80));
        check("8080 is not", false, CdnFront.isTlsPort(8080));
        check("alternate entry port kept", 2053,
                CdnFront.entryPort(ProxyConfig.parse(
                        "vless://u@a.com:2053?security=tls&type=ws#n")));
        check("odd entry port becomes 443", 443,
                CdnFront.entryPort(ProxyConfig.parse(
                        "vless://u@a.com:12345?security=tls&type=ws#n")));

        check("hostname recognised", true, CdnFront.isHostname("a.example.com"));
        check("ipv4 is not a hostname", false, CdnFront.isHostname("104.16.5.9"));
        check("ipv6 is not a hostname", false, CdnFront.isHostname("2001:db8::1"));
        check("bare word is not a hostname", false, CdnFront.isHostname("localhost"));
    }

    // ---------------------------------------------------------------- ranges

    static void ranges() {
        EdgeRanges edges = EdgeRanges.fallback();
        check("fallback prefix count", 15, edges.prefixCount());
        check("fallback address count", 1524736L, edges.addressCount());
        check("known edge recognised", true, edges.contains("104.16.5.9"));
        check("second range recognised", true, edges.contains("172.64.1.1"));
        check("outsider rejected", false, edges.contains("8.8.8.8"));
        check("garbage rejected", false, edges.contains("not an address"));
        check("octet overflow rejected", false, edges.contains("104.16.5.999"));

        EdgeRanges live = EdgeRanges.parse("104.16.0.0/13\n172.64.0.0/13\n");
        check("live list parsed", 2, live.prefixCount());
        check("live list used", false, live.contains("173.245.48.1"));

        // A captive portal answers every request with a login page. Treating that as the list
        // would leave the scanner with nothing to search and no sign anything went wrong.
        check("html body falls back", 15, EdgeRanges.parse("<html>hi</html>").prefixCount());
        check("empty body falls back", 15, EdgeRanges.parse("").prefixCount());
        check("null body falls back", 15, EdgeRanges.parse(null).prefixCount());

        check("prefix maths", 0L, EdgeRanges.range("0.0.0.0/0")[0]);
        check("prefix maths end", 4294967295L, EdgeRanges.range("0.0.0.0/0")[1]);
        check("host bits are masked off", EdgeRanges.range("104.16.0.0/13")[0],
                EdgeRanges.range("104.16.5.9/13")[0]);
        check("address round trip", "104.16.5.9",
                EdgeRanges.toAddress(EdgeRanges.toLong("104.16.5.9")));
    }

    static void sampling() {
        EdgeRanges edges = EdgeRanges.fallback();
        Random random = new Random(1);

        List<String> sample = edges.sample(2, 500, random);
        check("sample honours the limit", 500, sample.size());
        boolean allInside = true;
        boolean noBroadcast = true;
        for (String address : sample) {
            if (!edges.contains(address)) allInside = false;
            String last = address.substring(address.lastIndexOf('.') + 1);
            if ("0".equals(last) || "255".equals(last)) noBroadcast = false;
        }
        check("sample stays inside the ranges", true, allInside);
        check("sample skips .0 and .255", true, noBroadcast);

        // Spread is the point. A sweep that walks the space in order spends its whole budget in
        // one prefix and learns one prefix's worth of nothing.
        java.util.Set<String> blocks = new java.util.LinkedHashSet<>();
        for (String address : sample) blocks.add(address.substring(0, address.lastIndexOf('.')));
        check("sample is spread over many blocks", true, blocks.size() > 200);

        check("zero per block gives nothing", 0, edges.sample(0, 100, random).size());
        check("zero limit gives nothing", 0, edges.sample(2, 0, random).size());

        List<String> near = edges.neighbours("104.16.5.9", 6, random);
        check("neighbour count", 6, near.size());
        boolean sameBlock = true;
        for (String address : near) {
            if (!address.startsWith("104.16.5.")) sameBlock = false;
            if (address.equals("104.16.5.9")) sameBlock = false;
        }
        check("neighbours stay in the block and exclude the seed", true, sameBlock);
        check("neighbours of junk are empty", 0, edges.neighbours("nope", 4, random).size());
    }

    // ---------------------------------------------------------------- exporting

    static void exporting() {
        // Live pools are full of allowInsecure. Xray removed it and now rejects the whole config
        // rather than ignoring it, so leaving it in produces configs that every current client
        // refuses — indistinguishable, from the outside, from servers that are simply dead.
        ProxyConfig unsafe = ProxyConfig.parse(
                "vless://u@a.com:443?security=tls&type=ws&allowInsecure=1&insecure=0&host=a.com#n");
        ProxyConfig cleaned = Exporter.clean(unsafe, "JMC", 1);
        check("allowInsecure removed", "", cleaned.get("allowInsecure"));
        check("insecure removed", "", cleaned.get("insecure"));
        check("everything else kept", "ws", cleaned.transport());
        check("renamed", "JMC 1", cleaned.label);
        check("rejected params gone from the link", false,
                cleaned.toUri().toLowerCase(java.util.Locale.US).contains("insecure"));

        List<ProxyConfig> results = new java.util.ArrayList<>();
        ProxyConfig base = ProxyConfig.parse(
                "vless://u@a.com:443?security=tls&type=ws&host=a.com#@somechannel");
        results.add(CdnFront.front(base, "104.16.0.1", 443));
        results.add(CdnFront.front(base, "172.64.0.1", 443));   // same server, another door
        results.add(CdnFront.front(base, "104.16.0.1", 443));   // an exact repeat

        String subscription = Exporter.subscription(results, "JMC");
        check("exact repeat folded away", 2, subscription.split("\n").length);
        check("two doors both kept", true,
                subscription.contains("104.16.0.1") && subscription.contains("172.64.0.1"));
        check("numbering runs over the output", true, subscription.contains("JMC%202"));
        check("nobody else's channel survives", false, subscription.contains("somechannel"));
        check("no subscription headers", false, subscription.contains("profile-title"));

        String untagged = Exporter.subscription(results, "");
        check("no tag means no names", false, untagged.contains("#"));

        check("base64 output decodes back", true,
                new String(java.util.Base64.getDecoder().decode(Exporter.encoded(results, "JMC")),
                        java.nio.charset.StandardCharsets.UTF_8).startsWith("vless://"));
        check("empty input is empty output", "",
                Exporter.subscription(new java.util.ArrayList<ProxyConfig>(), "JMC"));
    }

    // ---------------------------------------------------------------- tunnelling

    /**
     * The probe run against a stub that behaves like a real endpoint. Everything below the
     * protocol is left out on purpose: a socket pair is a socket pair, and the parts worth
     * testing are the header bytes and the framing.
     */
    static void tunnelling() {
        check("uuid to bytes", 16,
                TunnelProbe.uuidBytes("11111111-2222-3333-4444-555555555555").length);
        check("first byte of the uuid", 0x11,
                TunnelProbe.uuidBytes("11111111-2222-3333-4444-555555555555")[0] & 0xff);
        check("short uuid refused", null, TunnelProbe.uuidBytes("1234"));
        check("non-hex uuid refused", null,
                TunnelProbe.uuidBytes("zzzzzzzz-2222-3333-4444-555555555555"));

        // The one fixed value in RFC 6455. If the accept hash is wrong the upgrade is a lie, and
        // a middlebox happily answering 101 to anything would otherwise read as success.
        check("websocket accept hash", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                Ws.accept("dGhlIHNhbXBsZSBub25jZQ=="));

        check("vless response header stripped", "hi",
                new String(TunnelProbe.stripVlessResponse(
                        new byte[] { 0, 0, 'h', 'i' }), java.nio.charset.StandardCharsets.ISO_8859_1));
        check("vless addons skipped", "hi",
                new String(TunnelProbe.stripVlessResponse(
                        new byte[] { 0, 2, 9, 9, 'h', 'i' }), java.nio.charset.StandardCharsets.ISO_8859_1));
        check("truncated vless response refused", null,
                TunnelProbe.stripVlessResponse(new byte[] { 0 }));

        check("vless+ws can be proved", true, TunnelProbe.canProve(ProxyConfig.parse(
                "vless://11111111-2222-3333-4444-555555555555@a.com:443?security=tls&type=ws#n")));
        check("grpc cannot be proved here", false, TunnelProbe.canProve(ProxyConfig.parse(
                "vless://11111111-2222-3333-4444-555555555555@a.com:443?security=tls&type=grpc#n")));
        check("ss cannot be proved here", false,
                TunnelProbe.canProve(ProxyConfig.parse("ss://YWVzOnB3@1.2.3.4:80#n")));

        ProxyConfig vless = ProxyConfig.parse(
                "vless://11111111-2222-3333-4444-555555555555@cdn.example.com:443"
                        + "?security=tls&type=ws&host=cdn.example.com&path=%2Fws#n");
        check("a healthy endpoint reads as working",
                TunnelProbe.Stage.WORKING, stub(vless, StubMode.HEALTHY).stage);

        // The failure that matters. The tunnel opens, the handshake completes, and then nothing
        // comes back. Reporting that as success is how a scanner hands over a list of dead
        // configs that all looked fine.
        check("a silent tunnel is not working",
                TunnelProbe.Stage.NO_TRAFFIC, stub(vless, StubMode.SILENT).stage);
        check("a refused upgrade is its own failure",
                TunnelProbe.Stage.NO_UPGRADE, stub(vless, StubMode.REFUSE).stage);
        check("wrong credentials do not read as working", false,
                stub(vless, StubMode.WRONG_UUID).working());

        ProxyConfig trojan = ProxyConfig.parse(
                "trojan://hunter2@cdn.example.com:443?security=tls&type=ws&path=%2Fws#n");
        check("trojan proves too", TunnelProbe.Stage.WORKING, stub(trojan, StubMode.HEALTHY).stage);

        check("the host header carries the real name, not the address", "cdn.example.com",
                lastHost);
        check("the path is requested as published", "/ws", lastPath);
    }

    enum StubMode { HEALTHY, SILENT, REFUSE, WRONG_UUID }

    static volatile String lastHost = "";
    static volatile String lastPath = "";

    /** Runs one probe against a throwaway server on loopback and returns what the probe made of it. */
    static TunnelProbe.Result stub(ProxyConfig config, StubMode mode) {
        try (java.net.ServerSocket server = new java.net.ServerSocket(0)) {
            server.setSoTimeout(5000);
            Thread listener = new Thread(() -> serve(server, config, mode));
            listener.setDaemon(true);
            listener.start();

            try (java.net.Socket socket = new java.net.Socket("127.0.0.1", server.getLocalPort())) {
                socket.setSoTimeout(5000);
                return TunnelProbe.run(config, CdnFront.hostname(config),
                        socket.getInputStream(), socket.getOutputStream(), new Random(3));
            }
        } catch (Exception failure) {
            return new TunnelProbe.Result(TunnelProbe.Stage.NO_SOCKET, 0, failure.toString());
        }
    }

    static void serve(java.net.ServerSocket server, ProxyConfig config, StubMode mode) {
        try (java.net.Socket socket = server.accept()) {
            socket.setSoTimeout(5000);
            java.io.InputStream in = socket.getInputStream();
            java.io.OutputStream out = socket.getOutputStream();

            String request = Ws.readLine(in);
            lastPath = request == null ? "" : request.split(" ")[1];
            String key = null;
            String line;
            while ((line = Ws.readLine(in)) != null && !line.trim().isEmpty()) {
                int colon = line.indexOf(':');
                if (colon < 0) continue;
                String name = line.substring(0, colon).trim();
                String value = line.substring(colon + 1).trim();
                if ("Sec-WebSocket-Key".equalsIgnoreCase(name)) key = value;
                if ("Host".equalsIgnoreCase(name)) lastHost = value;
            }
            if (mode == StubMode.REFUSE) {
                out.write("HTTP/1.1 400 Bad Request\r\n\r\n".getBytes("ISO-8859-1"));
                out.flush();
                return;
            }
            out.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    + "Connection: Upgrade\r\nSec-WebSocket-Accept: " + Ws.accept(key)
                    + "\r\n\r\n").getBytes("ISO-8859-1"));
            out.flush();

            byte[] payload = readFrame(in);
            if (payload == null) return;
            if (mode == StubMode.SILENT) {
                Thread.sleep(120);
                return;                                     // opened, then nothing. The bad case.
            }
            if ("vless".equals(config.protocol)) {
                byte[] expected = TunnelProbe.uuidBytes(config.id);
                boolean matches = payload.length > 17;
                for (int i = 0; matches && i < 16; i++) {
                    if (payload[1 + i] != expected[i]) matches = false;
                }
                if (mode == StubMode.WRONG_UUID || !matches) return;
                writeFrame(out, concat(new byte[] { 0, 0 },
                        "HTTP/1.1 204 No Content\r\n\r\n".getBytes("ISO-8859-1")));
            } else {
                String head = new String(payload, 0, Math.min(56, payload.length), "ISO-8859-1");
                if (!head.equals(TunnelProbe.hex(
                        TunnelProbe.sha224(config.id.getBytes("UTF-8"))))) return;
                writeFrame(out, "HTTP/1.1 204 No Content\r\n\r\n".getBytes("ISO-8859-1"));
            }
            out.flush();
            Thread.sleep(80);
        } catch (Exception ignored) {
            // A stub that dies is a failed check somewhere else; nothing useful to say here.
        }
    }

    static byte[] readFrame(java.io.InputStream in) throws java.io.IOException {
        int first = in.read();
        if (first < 0) return null;
        int second = in.read();
        if (second < 0) return null;
        boolean masked = (second & 0x80) != 0;
        int length = second & 0x7f;
        if (length == 126) length = (in.read() << 8) | in.read();
        byte[] mask = new byte[4];
        if (masked) for (int i = 0; i < 4; i++) mask[i] = (byte) in.read();
        byte[] payload = new byte[length];
        int read = 0;
        while (read < length) {
            int got = in.read(payload, read, length - read);
            if (got < 0) return null;
            read += got;
        }
        if (masked) for (int i = 0; i < length; i++) payload[i] ^= mask[i & 3];
        return payload;
    }

    static void writeFrame(java.io.OutputStream out, byte[] payload) throws java.io.IOException {
        out.write(0x82);
        out.write(payload.length);                          // stub payloads stay under 126
        out.write(payload);
        out.flush();
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    // ---------------------------------------------------------------- harness

    static void check(String what, Object expected, Object actual) {
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        if (ok) {
            passed++;
        } else {
            failed++;
            System.out.println("FAIL  " + what + "\n      expected: " + expected
                    + "\n      actual:   " + actual);
        }
    }
}
