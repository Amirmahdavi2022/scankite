/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The whole run, from nothing to a list of configs that were proved to work.
 *
 * <p>Ordered by what each step costs. Opening a socket is cheap, so that goes first and throws
 * away most of the address space; proving a config end to end is expensive, so only the survivors
 * of everything earlier get that far.
 *
 * <p>Two budgets keep it honest on a phone. Concurrency is capped, because a few hundred
 * simultaneous connections into a CDN from a handset is both slow in practice and hard to
 * distinguish from a port scan. And the whole run is on a wall clock, because a scan that could
 * in principle finish in twenty minutes has already failed.
 */
final class Engine {

    /** Where the search is at, so the screen can say something true while it works. */
    interface Watcher {
        void phase(int step, int of, String detail);
        void found(Result result);
        void done(List<Result> results, String summary);
    }

    static final class Result {
        final ProxyConfig config;      // already fronted, cleaned and ready to hand over
        final String edge;
        final long millis;
        final String origin;           // the hostname it really reaches

        Result(ProxyConfig config, String edge, long millis, String origin) {
            this.config = config;
            this.edge = edge;
            this.millis = millis;
            this.origin = origin;
        }
    }

    private static final int SWEEP_ADDRESSES = 900;
    private static final int SWEEP_THREADS = 40;
    private static final int SWEEP_TIMEOUT_MS = 1400;
    private static final int PROVE_THREADS = 12;
    private static final int PROVE_TIMEOUT_MS = 7000;
    private static final int EDGES_KEPT = 14;
    private static final int WANTED = 12;
    private static final long BUDGET_MS = 150_000;

    private final File cache;
    private final Watcher watcher;
    private volatile boolean cancelled;

    Engine(File cache, Watcher watcher) {
        this.cache = cache;
        this.watcher = watcher;
    }

    void cancel() { cancelled = true; }

    void run() {
        long deadline = System.currentTimeMillis() + BUDGET_MS;
        Random random = new Random();
        List<Result> results = new ArrayList<>();

        // 1 — the address space -------------------------------------------------------------
        watcher.phase(1, 4, "");
        String published = Net.fetch(EdgeRanges.LIST_URL, 8000);
        EdgeRanges edges = EdgeRanges.parse(published);
        boolean live = published != null;

        // 2 — credentials -------------------------------------------------------------------
        watcher.phase(2, 4, "");
        List<ProxyConfig> pool = Sources.load(cache, watcher);
        List<ProxyConfig> frontable = new ArrayList<>();
        for (ProxyConfig config : pool) {
            if (CdnFront.frontable(config) && TunnelProbe.canProve(config)) frontable.add(config);
        }
        Collections.shuffle(frontable, random);
        if (frontable.isEmpty()) {
            watcher.done(results, "no-pool");
            return;
        }

        // 3 — the cheap sweep ---------------------------------------------------------------
        watcher.phase(3, 4, "");
        List<String> candidates = edges.sample(2, SWEEP_ADDRESSES, random);
        final List<Object[]> answered = Collections.synchronizedList(new ArrayList<Object[]>());
        final AtomicInteger tried = new AtomicInteger();

        ExecutorService sweep = Executors.newFixedThreadPool(SWEEP_THREADS);
        for (final String address : candidates) {
            sweep.submit(() -> {
                if (cancelled || System.currentTimeMillis() > deadline
                        || answered.size() >= EDGES_KEPT * 4) {
                    return;
                }
                long took = Net.tcpMillis(address, 443, SWEEP_TIMEOUT_MS);
                int done = tried.incrementAndGet();
                if (took >= 0) answered.add(new Object[] { address, took });
                if (done % 25 == 0) {
                    watcher.phase(3, 4, done + "/" + candidates.size() + " · " + answered.size());
                }
            });
        }
        sweep.shutdown();
        try {
            sweep.awaitTermination(Math.max(1, (deadline - System.currentTimeMillis()) / 2),
                    TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        sweep.shutdownNow();

        List<Object[]> reachable = new ArrayList<>(answered);
        Collections.sort(reachable, (a, b) -> Long.compare((Long) a[1], (Long) b[1]));
        if (reachable.isEmpty()) {
            watcher.done(results, "no-edge");
            return;
        }
        List<String> chosen = new ArrayList<>();
        for (Object[] entry : reachable) {
            if (chosen.size() >= EDGES_KEPT) break;
            chosen.add((String) entry[0]);
        }

        // 4 — the expensive proof -----------------------------------------------------------
        //
        // Pairs are built across both lists rather than nested, so one dead credential cannot
        // burn the whole budget on an address that was fine, and one blocked address cannot
        // condemn a credential that works.
        watcher.phase(4, 4, "");
        final List<Object[]> pairs = new ArrayList<>();
        for (int round = 0; round < 4; round++) {
            for (int i = 0; i < chosen.size(); i++) {
                int configIndex = (i + round * chosen.size()) % frontable.size();
                pairs.add(new Object[] { frontable.get(configIndex), chosen.get(i) });
            }
        }

        ExecutorService prove = Executors.newFixedThreadPool(PROVE_THREADS);
        final Set<String> origins = Collections.synchronizedSet(new LinkedHashSet<String>());
        final List<Result> found = Collections.synchronizedList(new ArrayList<Result>());
        List<Future<?>> running = new ArrayList<>();
        for (final Object[] pair : pairs) {
            running.add(prove.submit(() -> {
                if (cancelled || found.size() >= WANTED
                        || System.currentTimeMillis() > deadline) {
                    return;
                }
                ProxyConfig config = (ProxyConfig) pair[0];
                String edge = (String) pair[1];
                int port = CdnFront.entryPort(config);
                TunnelProbe.Result outcome = Net.probe(config, edge, port, PROVE_TIMEOUT_MS);
                if (!outcome.working()) return;

                // One working credential through six addresses is six configs, but they all die
                // together the day that server goes. Spread across origins instead.
                String origin = CdnFront.hostname(config);
                if (!origins.add(origin + "@" + edge)) return;

                Result result = new Result(CdnFront.front(config, edge, port), edge,
                        outcome.millis, origin);
                found.add(result);
                watcher.found(result);
            }));
        }
        prove.shutdown();
        try {
            prove.awaitTermination(Math.max(1, deadline - System.currentTimeMillis()),
                    TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
        prove.shutdownNow();
        for (Future<?> task : running) task.cancel(true);

        results.addAll(found);
        Collections.sort(results, (a, b) -> Long.compare(a.millis, b.millis));
        watcher.done(results, live ? "ok" : "ok-fallback-ranges");
    }
}
