/*
 * scankite — Copyright (C) 2026 amirmahdavi2023
 * Licensed under the GNU General Public License v3.0 or later. See LICENSE.
 */
package works.jmc.scankite;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;

/**
 * Runs the core against whatever the public pools are publishing right now.
 *
 * Not part of the test suite: it depends on other people's servers being up, and a suite that
 * goes red because somebody else's repository moved teaches nobody anything. It is here to
 * answer one question with real numbers — how much of a live pool this app can actually improve.
 */
public final class LiveCheck {
    public static void main(String[] args) throws Exception {
        String[][] sources = {
            {"0xRadikal/Free-v2ray-Configs/main/top100.txt", "radikal-top"},
            {"MahanKenway/Freedom-V2Ray/main/configs/vless_sub.txt", "freedom-vless"},
            {"MahanKenway/Freedom-V2Ray/main/configs/trojan_sub.txt", "freedom-trojan"},
            {"iboxz/free-v2ray-collector/main/main/mix.txt", "iboxz-mix"},
            {"V2RayRoot/V2RayConfig/main/Config/vless.txt", "v2rayroot-vless"},
            {"barry-far/V2ray-Config/main/Splitted-By-Protocol/trojan.txt", "barry-trojan"},
        };
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
        List<ProxyConfig> all = new ArrayList<>();
        for (String[] s : sources) {
            try {
                HttpResponse<String> r = http.send(HttpRequest.newBuilder()
                        .uri(URI.create("https://raw.githubusercontent.com/" + s[0]))
                        .timeout(Duration.ofSeconds(30)).build(),
                        HttpResponse.BodyHandlers.ofString());
                List<ProxyConfig> got = ProxyConfig.parseDocument(r.body());
                all.addAll(got);
                System.out.printf("  %-18s %3d parsed%n", s[1], got.size());
            } catch (IOException | InterruptedException e) {
                System.out.printf("  %-18s unreachable%n", s[1]);
            }
        }

        Map<String,Integer> byProtocol = new TreeMap<>();
        Map<String,Integer> refused = new TreeMap<>();
        Set<String> unique = new LinkedHashSet<>();
        int frontable = 0, branded = 0, labelSurvived = 0;
        EdgeRanges edges = EdgeRanges.fallback();
        List<ProxyConfig> examples = new ArrayList<>();

        for (ProxyConfig c : all) {
            unique.add(c.key());
            byProtocol.merge(c.protocol, 1, Integer::sum);
            if (!Watermark.brands(c.label).isEmpty()) branded++;
            if (CdnFront.frontable(c)) {
                frontable++;
                if (!Watermark.strip(c.label).isEmpty()) labelSurvived++;
                if (examples.size() < 3) examples.add(c);
            } else {
                refused.merge(CdnFront.reason(c), 1, Integer::sum);
            }
        }

        System.out.println("\nparsed        " + all.size() + "  (" + unique.size() + " distinct servers)");
        System.out.println("by protocol   " + byProtocol);
        System.out.println("frontable     " + frontable + "  ("
                + Math.round(100.0 * frontable / Math.max(1, all.size())) + "% of the pool)");
        System.out.println("carry a watermark  " + branded);
        System.out.println("\nleft alone, and why:");
        refused.entrySet().stream()
               .sorted((a,b) -> b.getValue() - a.getValue())
               .forEach(e -> System.out.printf("  %5d  %s%n", e.getValue(), e.getKey()));

        System.out.println("\nalready pointed at a cloudflare address: " +
                all.stream().filter(c -> edges.contains(c.address)).count());

        System.out.println("\nwhat a swap looks like on real entries:");
        Random random = new Random(7);
        for (ProxyConfig c : examples) {
            String edge = edges.sample(1, 1, random).get(0);
            ProxyConfig out = CdnFront.front(c, edge, CdnFront.entryPort(c))
                                      .withLabel(Watermark.rename("JMC", 1));
            System.out.println("  was:  " + c.protocol + "://" + c.address + ":" + c.port
                    + "  #" + c.label);
            System.out.println("  now:  " + abbreviate(out.toUri()));
            System.out.println("        reparses to " + ProxyConfig.parse(out.toUri()).address
                    + ", sni=" + ProxyConfig.parse(out.toUri()).get("sni"));
        }
    }
    static String abbreviate(String s) { return s.length() > 150 ? s.substring(0,150) + "..." : s; }
}
