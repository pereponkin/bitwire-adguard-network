# bitwire outbound blocklist for AdGuard

Automatically updated AdGuard network filters built from bitwire-it's [outbound IP blocklist](https://github.com/bitwire-it/ipblocklist). They block connections to listed destination IPs in AdGuard for Windows, Mac, and Android. They are separate from the RKS tracking-domain filter.

Choose one or more subscriptions. Add each URL as a **content-blocking custom filter**, not a DNS filter:

| Filter | Scope |
| --- | --- |
| [Possible C2 servers](https://raw.githubusercontent.com/pereponkin/bitwire-adguard-network/main/filters/c2.txt) | Cobalt Strike and other possible command-and-control addresses from named source feeds. |
| [Compromised hosts](https://raw.githubusercontent.com/pereponkin/bitwire-adguard-network/main/filters/compromised.txt) | Hosts reported as compromised by Emerging Threats. |
| [Tor exits](https://raw.githubusercontent.com/pereponkin/bitwire-adguard-network/main/filters/tor-exits.txt) | Tor exit addresses from the upstream Tor feeds. |
| [Tunnels and proxies](https://raw.githubusercontent.com/pereponkin/bitwire-adguard-network/main/filters/tunnels.txt) | Addresses from the upstream tunnels feed; may include services you use intentionally. |
| [Complete outbound list](https://raw.githubusercontent.com/pereponkin/bitwire-adguard-network/main/filters/bitwire-outbound.txt) | Every address in bitwire's outbound list, including addresses outside the named categories. Large on mobile devices. |

Category membership follows the original source feeds listed in each filter header. Each category is intersected with bitwire's current merged `outbound.txt`, preserving its exclusions. Categories can overlap, and the named categories do not cover the complete list.

- Windows: Ad blocking → Add filter → Custom filter → paste the URL.
- Android: Settings → Filtering → Filters → Custom filters → Add custom filter → paste the URL.

These filters use AdGuard's [`$network` rules](https://adguard.com/kb/general/ad-filtering/create-own-filters/#network). Browser extensions, AdGuard Home, and iOS do not support this rule type. The complete list is large and may increase resource use, especially on Android. Direct IP blocking is also possible in a firewall.

GitHub Actions checks the upstream lists every two hours. The generator validates entries, expands bounded CIDR ranges to individual IPv4 or IPv6 addresses, and commits only when output changes. Scheduled workflows can be delayed by GitHub.

The source list and this derived filter are attributed to [bitwire-it/ipblocklist](https://github.com/bitwire-it/ipblocklist) and distributed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/). Upstream sources and their terms are listed in the [source repository](https://github.com/bitwire-it/ipblocklist#license).
