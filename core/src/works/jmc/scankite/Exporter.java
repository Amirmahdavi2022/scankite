/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Turns a ranked list of results into something a client will accept.
 *
 * <p>Three jobs, and the last one is the one that bites. Duplicates get folded together, because
 * a pool republishes the same server under six names. Labels are rewritten, so nobody else's
 * channel rides along. And a short list of parameters is taken out, because they are known to
 * make a current core throw the whole config away.
 */
public final class Exporter {

    /**
     * Parameters that stop a modern core dead.
     *
     * <p>{@code allowInsecure} was removed from Xray outright, and it does not ignore it — the
     * config is rejected on sight. Pools are full of it, so a run that skips this step can hand
     * over a hundred configs that every up-to-date client silently refuses, which looks exactly
     * like a hundred dead servers.
     */
    private static final String[] REJECTED = { "allowInsecure", "allowinsecure", "insecure" };

    private Exporter() { }

    /**
     * One entry, cleaned and left unnamed.
     *
     * <p>Nothing goes on in place of the branding that came off. Putting our own name there
     * would be the same trick with a different name on it, and the client numbers the list
     * anyway.
     */
    public static ProxyConfig clean(ProxyConfig config, int index) {
        ProxyConfig out = config;
        for (String name : REJECTED) out = out.withParam(name, "");
        return out.withLabel("");
    }

    /**
     * The subscription body. Deduplicated on the link itself, so the same server entered through
     * two different addresses is kept — that is the whole point — while an exact repeat is not.
     */
    public static String subscription(List<ProxyConfig> results) {
        List<String> lines = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        int index = 1;
        for (ProxyConfig config : results) {
            if (config == null) continue;
            String uri = clean(config, index).toUri();
            String identity = uri.contains("#") ? uri.substring(0, uri.lastIndexOf('#')) : uri;
            if (!seen.add(identity)) continue;
            lines.add(uri);
            index++;
        }
        return String.join("\n", lines);
    }

    /**
     * The same thing base64'd, which is what most clients expect when they are handed a URL.
     *
     * <p>Deliberately without the {@code #profile-title} and {@code #support-url} headers the
     * pools use. Those are how a subscription puts somebody's channel name at the top of your
     * client, and adding our own would be the same trick with a different name on it.
     */
    public static String encoded(List<ProxyConfig> results) {
        return Base64.getEncoder().encodeToString(
                subscription(results).getBytes(StandardCharsets.UTF_8));
    }
}
