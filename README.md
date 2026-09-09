# scankite

Finds Cloudflare edge addresses that work **on your network**, then rebuilds working configs around them.

Most clean-IP scanners stop at a list of addresses. An address on its own doesn't get you online, so you're left doing the fiddly part by hand. This one carries it through to a config you can actually import.

---

## The idea

If a config reaches its server through Cloudflare, it doesn't care which Cloudflare address you enter by. Routing happens on the hostname in the TLS handshake and the Host header, not on the address you dialled.

That makes the address a free variable. The one the publisher put in the link might be blocked or slow where you are, and another one might be fine. Same credentials, same server, different door.

So: take a config, work out whether it's CDN-fronted, scan for an edge address that answers from your phone, and write the config back out with the new address in front. Nothing else about it changes.

Two things this doesn't work on, and they're excluded on purpose:

- **REALITY** pins the connection to the real server's certificate. There's no CDN in the path to swap.
- **Hysteria2 and TUIC** run on QUIC, and Cloudflare doesn't carry UDP for normal customers.

## Does it actually apply to anything?

Checked against six live public sources on 2026-09-09:

| | |
|---|---|
| configs parsed | 1562 (929 distinct servers) |
| can have their address swapped | **686, about 44%** |
| already sitting on a Cloudflare address | 315 |
| carrying somebody's channel watermark | 612 |

The 315 matter more than they look. Those are configs already pointing at a Cloudflare address, which is direct confirmation that the frontable/not-frontable call is reading the pool correctly rather than guessing.

Why the rest get left alone:

```
338  no tls to carry a hostname
287  reality pins the real server
181  transport unstated, so not cdn traffic
 43  addressed by ip, with no hostname anywhere
 26  plain tcp
```

## Watermarks

Every public pool stamps itself on what it publishes, in two places:

- each entry's `#label`, usually something like `US 🇺🇸 | @somechannel | 6F42E7`
- the document header, `#profile-title` and `#support-url`, which is what makes your client show a stranger's channel name at the top of an imported subscription

Both come off. What's kept is the part that describes the server instead of the publisher, so a country code or a flag survives and a Telegram handle doesn't. You can put your own tag on instead, or leave them unnamed. Unnamed is the default, and the output carries no header directives at all, because doing the same trick with a different name on it isn't much of an improvement.

## Where it is

The app builds and runs. **v0.1.0**, debug APK from the `android` workflow — open the latest run and grab `scankite-debug` from the artifacts.

One screen. Press the button and it does the rest: reads the pools, pulls Cloudflare's published address list, sweeps for addresses that answer from your phone, then proves configs end to end and hands you the ones that carried a real reply. Copy one, copy all, or copy the lot as a base64 subscription. English and Persian, switchable in the app rather than only in system settings, and the layout flips for RTL.

It's about 44 KB, because there are no dependencies in it at all. Not androidx, not Kotlin, no material library. A single screen doesn't need a support library, and a jar you left out can't break your build.

**Tested, 143 checks green on a plain JVM:**

- the parser and writer, the fronting logic, watermark removal, address ranges, export
- the WebSocket client, checked against RFC 6455's one fixed handshake value
- the full probe, run against a stub server that speaks VLESS and Trojan back — including a stub that opens the tunnel and then goes silent, because that's the case a scanner must not report as success

**Not done yet:**

- a byedpi hop, so a handshake being interfered with gets a second chance before the address is written off
- grpc and xhttp, which are frontable but can't be proved by this probe yet
- vmess gets swapped and exported, but not proved end to end

## How the search is ordered

Cheapest first, because the expensive step is expensive:

1. **Address list.** Cloudflare's published one, falling back to the built-in copy.
2. **Credentials.** All six pools at once, saved to disk afterwards. That saved copy is the point: these lists are blocked on exactly the networks where you need them, so a later run still has something to work from.
3. **Sweep.** Around 900 sampled addresses, two per /24, 40 at a time. Neighbours share a fate, so this throws away most of the space quickly.
4. **Proof.** Only survivors get here. Pairs are built across both lists rather than nested, so one dead credential can't burn the budget on an address that was fine.

The whole run is on a wall clock. A scan that could in principle finish in twenty minutes has already failed.

### Why the last step has to be that expensive

The cheap tests lie. A TCP connect proves a socket opened, which happens against a black hole. A TLS handshake proves the CDN answered, which it does for every address it owns whether your config is behind it or not. Even the WebSocket upgrade only proves something reached an origin.

None of that is traffic getting through, and the gap is where a filtered connection lives: the handshake completes, then nothing comes back. So the last step speaks the real protocol and asks for a real page over it. There's no cheaper way to know.

One detail that matters there: the probe never asks an endpoint to reach a Cloudflare address. A lot of these servers are Cloudflare Workers, and a Worker can't open a connection to a Cloudflare address at all, so a Cloudflare target fails every healthy Worker-backed endpoint and files it as dead.

## Two details worth knowing if you're reading the code

**Configs that name their host only by the address.** Plenty of published links carry no `sni` or `host` at all, because the address *was* the hostname and the client filled both in from it. Put a bare address in front without writing them out explicitly and the connection lands on an edge with nothing to route on. Both get materialised on every swap, whether or not they were there before.

**`allowInsecure`.** Xray removed it and now rejects the whole config on sight rather than ignoring it. Public pools are full of it. Skip that cleanup and you hand over a pile of configs that every current client refuses, which from the outside looks exactly like a pile of dead servers.

## Build

The core needs nothing but a JDK:

```sh
javac -d build $(find core/src core/test -name '*.java')
java -cp build works.jmc.scankite.Tests
```

The app:

```sh
cd android && ./gradlew assembleDebug
```

There's also a check that runs the core against the live pools, which is kept out of CI because a suite that goes red when somebody else's repository moves teaches you nothing:

```sh
javac -d build $(find core/src core/tools -name '*.java')
java -cp build works.jmc.scankite.LiveCheck
```

## Configs

None are shipped here. The pool lists are read over the network at runtime, the way any subscription client reads them, so nobody's files are redistributed in this repository.

## Licence

GPL-3.0. Fork it, change it, ship it — but if you hand out a build, the source and the copyright notices go with it. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
