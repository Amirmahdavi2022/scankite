/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Just enough JSON for a vmess payload, which is a flat object of strings and numbers.
 *
 * <p>Pulling in a JSON library for one shallow object would cost more than it is worth, and this
 * has to survive whatever a pool publishes, so it reads leniently and never throws: an object it
 * cannot make sense of comes back empty and the caller drops that line.
 */
final class FlatJson {

    private FlatJson() { }

    static Map<String, String> read(String json) {
        Map<String, String> out = new LinkedHashMap<>();
        if (json == null) return out;
        int i = json.indexOf('{');
        if (i < 0) return out;
        i++;

        while (i < json.length()) {
            i = skipSpace(json, i);
            if (i >= json.length() || json.charAt(i) == '}') break;
            if (json.charAt(i) == ',') { i++; continue; }
            if (json.charAt(i) != '"') return out;      // not a shape we understand

            StringBuilder name = new StringBuilder();
            i = readString(json, i, name);
            if (i < 0) return out;

            i = skipSpace(json, i);
            if (i >= json.length() || json.charAt(i) != ':') return out;
            i = skipSpace(json, i + 1);
            if (i >= json.length()) return out;

            StringBuilder value = new StringBuilder();
            if (json.charAt(i) == '"') {
                i = readString(json, i, value);
                if (i < 0) return out;
            } else {
                // A bare number, true/false, or null. Nested objects and arrays are not something
                // vmess uses, and treating one as a scalar would corrupt the rest of the parse.
                char c = json.charAt(i);
                if (c == '{' || c == '[') return out;
                while (i < json.length() && json.charAt(i) != ',' && json.charAt(i) != '}') {
                    value.append(json.charAt(i));
                    i++;
                }
            }
            String text = value.toString().trim();
            out.put(name.toString(), "null".equals(text) ? "" : text);
        }
        return out;
    }

    static String write(Map<String, String> fields) {
        StringBuilder out = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            if (!first) out.append(',');
            first = false;
            out.append('"').append(escape(entry.getKey())).append("\":\"")
               .append(escape(entry.getValue() == null ? "" : entry.getValue())).append('"');
        }
        return out.append('}').toString();
    }

    private static int skipSpace(String json, int i) {
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        return i;
    }

    /** Reads a quoted string starting at the opening quote; returns the index after the close. */
    private static int readString(String json, int i, StringBuilder into) {
        i++;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char next = json.charAt(i + 1);
                switch (next) {
                    case 'n': into.append('\n'); break;
                    case 't': into.append('\t'); break;
                    case 'r': into.append('\r'); break;
                    case 'b': into.append('\b'); break;
                    case 'f': into.append('\f'); break;
                    case 'u':
                        if (i + 5 < json.length()) {
                            try {
                                into.append((char) Integer.parseInt(json.substring(i + 2, i + 6), 16));
                            } catch (NumberFormatException bad) {
                                return -1;
                            }
                            i += 6;
                            continue;
                        }
                        return -1;
                    default: into.append(next);
                }
                i += 2;
                continue;
            }
            if (c == '"') return i + 1;
            into.append(c);
            i++;
        }
        return -1;
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.toString();
    }
}
