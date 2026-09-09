/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.io.File;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Where the credentials come from.
 *
 * <p>A clean address is a door with no room behind it. The credentials that make it useful are
 * published by people who run these servers and hand out the configs deliberately, so this reads
 * their lists the way any subscription client does. Nobody's files are shipped inside the app.
 *
 * <p>The copy on disk matters more than it looks. These lists are blocked on exactly the networks
 * where they are needed, so a run that can reach nothing still has yesterday's list to work from,
 * and yesterday's list is the only route back online.
 */
final class Sources {

    private static final String[][] LISTS = {
            { "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt", "radikal" },
            { "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/vless_sub.txt", "freedom" },
            { "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix.txt", "iboxz" },
            { "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/vless.txt", "v2rayroot" },
            { "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt", "barry" },
            { "https://raw.githubusercontent.com/MahanKenway/Freedom-V2Ray/main/configs/trojan_sub.txt", "freedom-t" },
    };

    private static final String CACHE = "pool.txt";
    private static final int TIMEOUT_MS = 12000;

    private Sources() { }

    /** Fetches every list at once, falls back to the saved copy, and saves what it got. */
    static List<ProxyConfig> load(File directory, Engine.Watcher watcher) {
        final List<String> bodies = Collections.synchronizedList(new ArrayList<String>());
        ExecutorService fetchers = Executors.newFixedThreadPool(LISTS.length);
        for (final String[] list : LISTS) {
            fetchers.submit(() -> {
                String body = Net.fetch(list[0], TIMEOUT_MS);
                if (body != null && body.contains("://")) {
                    bodies.add(body);
                    watcher.phase(2, 4, list[1]);
                }
            });
        }
        fetchers.shutdown();
        try {
            fetchers.awaitTermination(TIMEOUT_MS + 4000, TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        fetchers.shutdownNow();

        List<ProxyConfig> configs = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String body : new ArrayList<>(bodies)) {
            for (ProxyConfig config : ProxyConfig.parseDocument(body)) {
                if (seen.add(config.key())) configs.add(config);
            }
        }

        if (!configs.isEmpty()) {
            save(directory, configs);
            return configs;
        }
        return read(directory);
    }

    /** Only the frontable entries are kept, since nothing else would survive a later run. */
    private static void save(File directory, List<ProxyConfig> configs) {
        StringBuilder body = new StringBuilder();
        int kept = 0;
        for (ProxyConfig config : configs) {
            if (!CdnFront.frontable(config) || !TunnelProbe.canProve(config)) continue;
            body.append(config.toUri()).append('\n');
            if (++kept >= 800) break;
        }
        try (FileOutputStream out = new FileOutputStream(new File(directory, CACHE))) {
            out.write(body.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception unwritable) {
            // A cache that cannot be written costs the next offline run, not this one.
        }
    }

    private static List<ProxyConfig> read(File directory) {
        File file = new File(directory, CACHE);
        if (!file.exists()) return new ArrayList<>();
        try (RandomAccessFile in = new RandomAccessFile(file, "r")) {
            byte[] bytes = new byte[(int) Math.min(in.length(), 4_000_000L)];
            in.readFully(bytes);
            return ProxyConfig.parseDocument(new String(bytes, StandardCharsets.UTF_8));
        } catch (Exception unreadable) {
            return new ArrayList<>();
        }
    }
}
