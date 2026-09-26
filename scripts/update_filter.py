"""Convert bitwire's outbound IP list into AdGuard network rules."""

import argparse
import ipaddress
from pathlib import Path
from urllib.request import urlopen


SOURCE = "https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/outbound.txt"
OUTPUT = Path(__file__).resolve().parents[1] / "filters" / "bitwire-outbound.txt"
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


def convert(source: str) -> str:
    """Validate and expand the source into deterministic AdGuard rules."""
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

    rules = (
        f"[{address.compressed}]$network" if address.version == 6 else f"{address}$network"
        for address in sorted(addresses, key=lambda address: (address.version, int(address)))
    )
    return HEADER + "\n".join(rules) + "\n"


def main() -> None:
    """Fetch the current source and update the generated filter."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="Local source file for validation")
    args = parser.parse_args()

    if args.input:
        source = args.input.read_text(encoding="utf-8")
    else:
        with urlopen(SOURCE, timeout=60) as response:
            source = response.read(MAX_SOURCE_BYTES + 1)
        if len(source) > MAX_SOURCE_BYTES:
            raise ValueError("Source exceeds download size limit")
        source = source.decode("utf-8")

    result = convert(source)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != result:
        OUTPUT.write_text(result, encoding="utf-8", newline="\n")
    print(f"Generated {result.count('$network')} network rules")


if __name__ == "__main__":
    main()
