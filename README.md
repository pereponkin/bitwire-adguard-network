# bitwire outbound blocklist for AdGuard

An automatically updated AdGuard network filter built from bitwire-it's [outbound IP blocklist](https://github.com/bitwire-it/ipblocklist). It blocks connections to listed destination IPs in AdGuard for Windows, Mac, and Android. It is separate from the RKS tracking-domain filter.

Subscribe to this URL as a **content-blocking custom filter**, not a DNS filter:

```text
https://raw.githubusercontent.com/pereponkin/bitwire-adguard-network/main/filters/bitwire-outbound.txt
```

- Windows: Ad blocking → Add filter → Custom filter → paste the URL.
- Android: Settings → Filtering → Filters → Custom filters → Add custom filter → paste the URL.

The filter uses AdGuard's [`$network` rules](https://adguard.com/kb/general/ad-filtering/create-own-filters/#network). Browser extensions, AdGuard Home, and iOS do not support this rule type. This is a large list and may increase resource use, especially on Android. Direct IP blocking is also possible in a firewall.

GitHub Actions checks the upstream list every two hours. The generator validates every entry, expands small CIDR ranges to individual IPv4 or IPv6 addresses, and commits only when the output changes. Scheduled workflows can be delayed by GitHub.

The source list and this derived filter are attributed to [bitwire-it/ipblocklist](https://github.com/bitwire-it/ipblocklist) and distributed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/). Upstream sources and their terms are listed in the [source repository](https://github.com/bitwire-it/ipblocklist#license).
