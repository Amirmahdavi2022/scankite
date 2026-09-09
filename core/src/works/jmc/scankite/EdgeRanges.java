/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * Cloudflare's address space, and how to search it without spending all afternoon.
 *
 * <p>There are about 1.5 million addresses here. Testing them one by one is not a plan, and
 * hammering a CDN with a million connections from a phone is not a good look either. What makes
 * it tractable is that they do not behave independently: whether a path works is decided by
 * routing and by filtering equipment, and both operate on prefixes. Neighbours share a fate.
 *
 * <p>So the search samples a couple of addresses from each /24, throws away the blocks where
 * nothing answered, and looks harder at the ones where something did.
 */
public final class EdgeRanges {

    /**
     * Used only when the published list cannot be fetched.
     *
     * <p>Cross-checked against two independent copies rather than written from memory, but it is
     * still a snapshot: Cloudflare adds ranges, and a stale list quietly shrinks the search
     * instead of failing. {@link #parse} on the live list is always preferred.
     */
    public static final String[] FALLBACK = {
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
            "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
            "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    };

    /** Where the authoritative list lives. */
    public static final String LIST_URL = "https://www.cloudflare.com/ips-v4";

    private final List<long[]> blocks = new ArrayList<>();   // { first, last } inclusive

    private EdgeRanges(List<String> prefixes) {
        for (String prefix : prefixes) {
            long[] block = range(prefix);
            if (block != null) blocks.add(block);
        }
    }

    public static EdgeRanges fallback() {
        List<String> prefixes = new ArrayList<>();
        for (String prefix : FALLBACK) prefixes.add(prefix);
        return new EdgeRanges(prefixes);
    }

    /**
     * Reads the published list. Returns the fallback when the body yields nothing usable, so a
     * captive portal serving an HTML error page cannot empty the search space.
     */
    public static EdgeRanges parse(String body) {
        List<String> prefixes = new ArrayList<>();
        if (body != null) {
            for (String line : body.split("\\r?\\n")) {
                String text = line.trim();
                if (text.matches("\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}")) prefixes.add(text);
            }
        }
        return prefixes.isEmpty() ? fallback() : new EdgeRanges(prefixes);
    }

    public int prefixCount() { return blocks.size(); }

    public long addressCount() {
        long total = 0;
        for (long[] block : blocks) total += block[1] - block[0] + 1;
        return total;
    }

    /** Whether an address belongs to the CDN — used to tell a fronted config from a direct one. */
    public boolean contains(String address) {
        long value = toLong(address);
        if (value < 0) return false;
        for (long[] block : blocks) {
            if (value >= block[0] && value <= block[1]) return true;
        }
        return false;
    }

    /**
     * A first sweep: {@code perBlock} addresses from each /24, spread across the whole space.
     *
     * <p>Sampled rather than taken in order. Consecutive addresses in one block tell you almost
     * nothing new, and a scan that walks an address space from the bottom is both slower to find
     * an answer and more obviously a scan.
     */
    public List<String> sample(int perBlock, int limit, Random random) {
        List<String> out = new ArrayList<>();
        if (perBlock <= 0 || limit <= 0) return out;

        List<long[]> slashTwentyFours = new ArrayList<>();
        for (long[] block : blocks) {
            for (long base = block[0] & 0xffffff00L; base <= block[1]; base += 256) {
                if (base >= block[0]) slashTwentyFours.add(new long[] { base });
            }
        }
        shuffle(slashTwentyFours, random);

        Set<String> seen = new LinkedHashSet<>();
        for (long[] block : slashTwentyFours) {
            for (int i = 0; i < perBlock && seen.size() < limit; i++) {
                // .0 and .255 are skipped: broadcast and network addresses are not worth a probe.
                long host = 1 + random.nextInt(254);
                seen.add(toAddress(block[0] + host));
            }
            if (seen.size() >= limit) break;
        }
        out.addAll(seen);
        return out;
    }

    /** A second, closer look at a block that already answered once. */
    public List<String> neighbours(String address, int count, Random random) {
        List<String> out = new ArrayList<>();
        long value = toLong(address);
        if (value < 0 || count <= 0) return out;
        long base = value & 0xffffff00L;
        Set<String> seen = new LinkedHashSet<>();
        for (int guard = 0; guard < count * 8 && seen.size() < count; guard++) {
            long host = 1 + random.nextInt(254);
            String candidate = toAddress(base + host);
            if (!candidate.equals(address)) seen.add(candidate);
        }
        out.addAll(seen);
        return out;
    }

    // ---------------------------------------------------------------- arithmetic

    static long[] range(String prefix) {
        int slash = prefix.indexOf('/');
        if (slash < 0) return null;
        long base = toLong(prefix.substring(0, slash));
        int bits;
        try {
            bits = Integer.parseInt(prefix.substring(slash + 1).trim());
        } catch (NumberFormatException bad) {
            return null;
        }
        if (base < 0 || bits < 0 || bits > 32) return null;
        long size = 1L << (32 - bits);
        long first = base & ~(size - 1);
        return new long[] { first, first + size - 1 };
    }

    static long toLong(String address) {
        if (address == null) return -1;
        String[] parts = address.trim().split("\\.");
        if (parts.length != 4) return -1;
        long value = 0;
        for (String part : parts) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException bad) {
                return -1;
            }
            if (octet < 0 || octet > 255) return -1;
            value = (value << 8) | octet;
        }
        return value;
    }

    static String toAddress(long value) {
        return ((value >> 24) & 0xff) + "." + ((value >> 16) & 0xff) + "."
                + ((value >> 8) & 0xff) + "." + (value & 0xff);
    }

    private static void shuffle(List<long[]> items, Random random) {
        for (int i = items.size() - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            long[] swap = items.get(i);
            items.set(i, items.get(j));
            items.set(j, swap);
        }
    }
}
