/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Everything that touches the network from the phone. */
final class Net {

    private Net() { }

    /** How long a TCP connect took, or -1 if it did not. */
    static long tcpMillis(String address, int port, int timeoutMs) {
        long started = System.nanoTime();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), timeoutMs);
            return (System.nanoTime() - started) / 1_000_000L;
        } catch (Exception unreachable) {
            return -1;
        }
    }

    /**
     * The full test: dial the address, hand the CDN a hostname it does not belong to, then speak
     * the config's protocol through it and ask for a real page.
     *
     * <p>Setting the server name by hand is the part that makes this work at all. Connecting by
     * address means the socket has no name to derive an SNI from, and without one the CDN has no
     * idea whose traffic this is and answers with its own error page.
     */
    static TunnelProbe.Result probe(ProxyConfig config, String edge, int port, int timeoutMs) {
        String hostname = CdnFront.sniOf(config);
        String route = CdnFront.hostOf(config);
        if (hostname.isEmpty()) {
            return new TunnelProbe.Result(TunnelProbe.Stage.NO_SOCKET, 0, "no hostname");
        }
        Socket plain = new Socket();
        try {
            plain.connect(new InetSocketAddress(edge, port), timeoutMs);
            plain.setSoTimeout(timeoutMs);

            SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                    .createSocket(plain, hostname, port, true);
            SSLParameters parameters = tls.getSSLParameters();
            List<SNIServerName> names = new ArrayList<>();
            names.add(new SNIHostName(hostname));
            parameters.setServerNames(names);
            // Certificate validation is left switched on. Turning it off would make a hijacked
            // handshake indistinguishable from a working one, which is the opposite of the
            // question this app exists to answer.
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            tls.setSSLParameters(parameters);
            tls.setSoTimeout(timeoutMs);
            tls.startHandshake();

            TunnelProbe.Result result = TunnelProbe.run(config, hostname, route,
                    tls.getInputStream(), tls.getOutputStream(), new Random());
            try { tls.close(); } catch (Exception ignored) { }
            return result;
        } catch (Exception failure) {
            try { plain.close(); } catch (Exception ignored) { }
            String message = failure.getMessage() == null
                    ? failure.getClass().getSimpleName() : failure.getMessage();
            return new TunnelProbe.Result(TunnelProbe.Stage.NO_SOCKET, timeoutMs, message);
        }
    }

    /** A plain GET, used for the address list and the pool files. */
    static String fetch(String url, int timeoutMs) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(timeoutMs);
            connection.setReadTimeout(timeoutMs);
            connection.setRequestProperty("User-Agent", "scankite");
            if (connection.getResponseCode() / 100 != 2) return null;
            try (InputStream in = connection.getInputStream()) {
                ByteArrayOutputStream body = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int read;
                // Pool dumps run to megabytes and are pulled over a phone connection. Past a
                // couple of megabytes there is nothing left to learn, only data to pay for.
                while ((read = in.read(buffer)) > 0 && body.size() < 3_000_000) {
                    body.write(buffer, 0, read);
                }
                return new String(body.toByteArray(), StandardCharsets.UTF_8);
            }
        } catch (Exception unreachable) {
            return null;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    /** Sorts a list of measurements fastest first. */
    static void byLatency(List<long[]> measurements) {
        Collections.sort(measurements, (a, b) -> Long.compare(a[1], b[1]));
    }
}
