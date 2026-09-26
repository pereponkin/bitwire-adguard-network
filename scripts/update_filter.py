"""Convert bitwire's outbound IP list into AdGuard network rules."""

import argparse
import ipaddress
from pathlib import Path
from urllib.request import urlopen


SOURCE = "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt"
FILTERS = Path(__file__).resolve().parents[1] / "filters"
MAX_SOURCE_BYTES = 20_000_000
MAX_ADDRESSES = 500_000
HEADER = """! Title: bitwire outbound IP blocklist for AdGuard
! Description: Network rules derived from bitwire-it/ipblocklist outbound.txt.
! Homepage: https://github.com/bitwire-it/ipblocklist
! Source: https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt
! License: CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/)
! Expires: 2 hours
! Requires AdGuard for Windows, Mac, or Android; add as a content-blocking filter.
"""
CATEGORIES = {
    "tor-exits": (
        "Tor exit nodes",
        (
            "https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/tor-exit.txt",
            "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
            "https://secureupdates.checkpoint.com/IP-list/TOR.txt",
            "https://raw.githubusercontent.com/borestad/firehol-mirror/refs/heads/main/tor_exits.ipset",
            "https://raw.githubusercontent.com/borestad/firehol-mirror/refs/heads/main/iblocklist_onion_router.netset",
        ),
    ),
    "c2": (
        "Possible command-and-control servers",
        (
            "https://raw.githubusercontent.com/CriticalPathSecurity/Public-Intelligence-Feeds/refs/heads/master/cps_cobaltstrike_ip.txt",
            "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/refs/heads/master/feeds/IPC2s.csv",
            "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/refs/heads/master/feeds/IPC2s-90day.csv",
        ),
    ),
    "compromised": (
        "Reported compromised hosts",
        (
            "https://raw.githubusercontent.com/borestad/firehol-mirror/refs/heads/main/et_compromised.ipset",
            "https://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
        ),
    ),
    "tunnels": (
        "Tunnels and proxies",
        ("https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Lists/Tunnels",),
    ),
}


def fetch(url: str) -> str:
    """Download a bounded UTF-8 source list."""
    with urlopen(url, timeout=60) as response:
        data = response.read(MAX_SOURCE_BYTES + 1)
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError(f"Source exceeds download size limit: {url}")
    return data.decode("utf-8")


def outbound_addresses(source: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Validate and expand the upstream aggregate list."""
    networks = []
    address_count = 0
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=True)
        except ValueError as error:
            raise ValueError(f"Invalid source line {line_number}: {line}") from error
        address_count += network.num_addresses
        if address_count > MAX_ADDRESSES:
            raise ValueError(f"Source expands to more than {MAX_ADDRESSES} addresses")
        networks.append(network)

    if len(networks) < 1_000:
        raise ValueError(f"Source has only {len(networks)} entries; refusing to publish")

    addresses = set()
    for network in networks:
        addresses.update(network)
    return addresses


def category_addresses(source: str, url: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Read addresses from a selected original source."""
    addresses = set()
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = [line.split(",", 1)[0]] if url.endswith(".csv") else line.split()
        for token in tokens:
            address = token.replace("[", "", 1).replace("]", "", 1) if token.startswith("[") else token
            try:
                network = ipaddress.ip_network(address, strict=False)
            except ValueError as error:
                raise ValueError(f"Invalid {url} line {line_number}: {token}") from error
            if network.num_addresses > MAX_ADDRESSES:
                raise ValueError(f"Network too large in {url} line {line_number}: {token}")
            addresses.update(network)
            if len(addresses) > MAX_ADDRESSES:
                raise ValueError(f"Category source has more than {MAX_ADDRESSES} addresses: {url}")
    if not addresses:
        raise ValueError(f"Category source is empty: {url}")
    return addresses


def render(addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address], header: str) -> str:
    """Format exact addresses as AdGuard network rules."""
    rules = (
        f"[{address.compressed}]$network" if address.version == 6 else f"{address}$network"
        for address in sorted(addresses, key=lambda address: (address.version, int(address)))
    )
    return header + "\n".join(rules) + "\n"


def write_filter(path: Path, content: str) -> None:
    """Write a filter only when its contents change."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists() or path.read_text(encoding="utf-8") != content:
        path.write_text(content, encoding="utf-8", newline="\n")


def convert(source: str) -> str:
    """Validate and expand the source into deterministic AdGuard rules."""
    return render(outbound_addresses(source), HEADER)


def main() -> None:
    """Fetch the current source and update the generated filter."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Local source file for validation")
    args = parser.parse_args()

    source = args.input.read_text(encoding="utf-8") if args.input else fetch(SOURCE)
    full = outbound_addresses(source)
    write_filter(FILTERS / "bitwire-outbound.txt", render(full, HEADER))
    print(f"Full filter: {len(full)} network rules")

    if args.input:
        return

    for name, (title, urls) in CATEGORIES.items():
        addresses = set()
        for url in urls:
            addresses.update(category_addresses(fetch(url), url))
        addresses.intersection_update(full)
        if not addresses:
            raise ValueError(f"Category {name} has no addresses in the outbound list")
        header = (
            f"! Title: bitwire outbound — {title}\n"
            f"! Description: Source-based subset of bitwire-it/ipblocklist outbound.txt.\n"
            f"! Homepage: https://github.com/bitwire-it/ipblocklist\n"
            f"! Source: {SOURCE}\n"
            + "".join(f"! Category source: {url}\n" for url in urls)
            + "! License: CC BY-NC-SA 4.0 (https://creativecommons.org/licenses/by-nc-sa/4.0/)\n"
            + "! Expires: 2 hours\n"
        )
        write_filter(FILTERS / f"{name}.txt", render(addresses, header))
        print(f"{title}: {len(addresses)} network rules")


if __name__ == "__main__":
    main()
