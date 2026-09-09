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

The core is done and tested. The Android app around it isn't built yet.

**Done, 125 checks green:**

- parser and writer for vless, vmess, trojan, ss, hysteria2, tuic, including base64-wrapped documents
- the fronting logic, which is the part that actually decides whether the idea works
- watermark removal
- Cloudflare address ranges, with sampling that spreads across /24s instead of walking the space in order
- export, with the parameters that break current cores taken out

**Next:**

- the scanner itself, running on the device
- real testing through an Xray core rather than a bare TCP connect, because a socket that opens and carries nothing is a failure, not a success
- a byedpi hop, so a handshake being interfered with gets a second chance before the address is written off
- the UI

## Two details worth knowing if you're reading the code

**Configs that name their host only by the address.** Plenty of published links carry no `sni` or `host` at all, because the address *was* the hostname and the client filled both in from it. Put a bare address in front without writing them out explicitly and the connection lands on an edge with nothing to route on. Both get materialised on every swap, whether or not they were there before.

**`allowInsecure`.** Xray removed it and now rejects the whole config on sight rather than ignoring it. Public pools are full of it. Skip that cleanup and you hand over a pile of configs that every current client refuses, which from the outside looks exactly like a pile of dead servers.

## Build

Core only, for now. No dependencies, no build system:

```sh
javac -d build $(find core/src core/test -name '*.java')
java -cp build works.jmc.scankite.Tests
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
