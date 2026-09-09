/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Takes somebody else's advertising off a config.
 *
 * <p>Every public pool stamps its channel on what it publishes, in two places. Each entry carries
 * a #label like {@code US | @somechannel | 6F42E7}, and the document itself opens with directives
 * such as {@code #profile-title} and {@code #support-url}, which is what makes a client display a
 * stranger's channel name at the top of an imported subscription.
 *
 * <p>Both get removed here. What is kept is the part that describes the server rather than the
 * publisher — a country code or a flag is information; a Telegram handle is not.
 */
public final class Watermark {

    /** Document-level lines a client reads as subscription metadata. */
    private static final String[] DIRECTIVES = {
            "profile-title", "profile-update-interval", "subscription-userinfo",
            "support-url", "profile-web-page-url", "announce", "announce-url",
    };

    private Watermark() { }

    /** True for a line that names or advertises whoever published the document. */
    public static boolean isDirective(String line) {
        if (line == null) return false;
        String text = line.trim();
        if (!text.startsWith("#")) return false;
        String body = text.substring(1).trim().toLowerCase(Locale.US);
        for (String directive : DIRECTIVES) {
            if (body.startsWith(directive + ":") || body.startsWith(directive + "=")) return true;
        }
        return false;
    }

    /**
     * Links and handles, which have to come out whole.
     *
     * <p>Cutting the label into pieces first would tear {@code t.me/somechannel} into a domain
     * and a leftover word, and the leftover word is the channel name — the thing being removed.
     */
    private static final java.util.regex.Pattern WHOLE = java.util.regex.Pattern.compile(
            "(?i)(https?://\\S+|(?:www\\.)?t\\.me/\\S+|telegram\\.(?:me|org)/\\S+|@[\\w_.]{2,})");

    /** Every piece of branding found in a label, for reporting what was taken out. */
    public static List<String> brands(String label) {
        List<String> found = new ArrayList<>();
        if (label == null || label.isEmpty()) return found;
        Set<String> seen = new LinkedHashSet<>();

        java.util.regex.Matcher matcher = WHOLE.matcher(label);
        while (matcher.find()) {
            String hit = matcher.group().trim();
            if (seen.add(hit.toLowerCase(Locale.US))) found.add(hit);
        }
        for (String piece : split(WHOLE.matcher(label).replaceAll(" "))) {
            String trimmed = piece.trim();
            if (isBranding(trimmed) && seen.add(trimmed.toLowerCase(Locale.US))) {
                found.add(trimmed);
            }
        }
        return found;
    }

    /**
     * The label with the branding gone. Comes back empty when the label was nothing but
     * branding, which is the common case.
     */
    public static String strip(String label) {
        if (label == null || label.isEmpty()) return "";
        StringBuilder out = new StringBuilder();
        for (String piece : split(WHOLE.matcher(label).replaceAll(" "))) {
            String trimmed = piece.trim();
            if (trimmed.isEmpty() || isBranding(trimmed)) continue;
            if (out.length() > 0) out.append(' ');
            out.append(trimmed);
        }
        return collapse(out.toString());
    }

    /**
     * The name to publish under. A tag of your own if you set one, otherwise nothing —
     * an unlabelled config is honest, and the client numbers them anyway.
     */
    public static String rename(String tag, int index) {
        if (tag == null || tag.trim().isEmpty()) return "";
        return tag.trim() + " " + index;
    }

    // ---------------------------------------------------------------- internals

    /** Labels are conventionally cut up by pipes, dashes and brackets rather than spaces. */
    private static List<String> split(String label) {
        List<String> pieces = new ArrayList<>();
        for (String piece : label.split("[|\\[\\]{}()<>•·,;/\\\\]|\\s[-–—]\\s|\\s{2,}")) {
            if (!piece.trim().isEmpty()) pieces.add(piece);
        }
        if (pieces.isEmpty()) pieces.add(label);
        return pieces;
    }

    private static boolean isBranding(String piece) {
        String lower = piece.toLowerCase(Locale.US);
        if (lower.startsWith("@")) return true;                       // @channel
        if (lower.contains("t.me") || lower.contains("telegram")) return true;
        if (lower.startsWith("http://") || lower.startsWith("https://")) return true;
        if (lower.contains("://")) return true;
        if (lower.matches(".*\\b(join|subscribe|channel|sponsor|buy|free\\s*vpn)\\b.*")) return true;

        // A bare word carrying a channel-ish marker. Deliberately narrow: plenty of legitimate
        // labels contain a city or a provider name, and stripping those loses real information.
        if (lower.matches("[a-z0-9_]*(vpn|v2ray|vless|proxy|config|net|dns|tunnel)[a-z0-9_]*")
                && lower.length() > 4 && !lower.matches("(vpn|v2ray|vless|proxy|config|net|dns|tunnel)")) {
            return true;
        }
        return false;
    }

    private static String collapse(String value) {
        return value.replaceAll("\\s+", " ").replaceAll("^[\\s|,;:.\\-–—]+", "")
                    .replaceAll("[\\s|,;:.\\-–—]+$", "").trim();
    }
}
