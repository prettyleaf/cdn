#!/usr/bin/env python3
"""Generate Mihomo rule-provider binary files (.mrs) from plain CIDR lists."""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = [
    "akamai",
    "aws",
    "cdn77",
    "cloudflare",
    "cogent",
    "constant",
    "contabo",
    "datacamp",
    "digitalocean",
    "fastly",
    "gcore",
    "hetzner",
    "melbicom",
    "meta",
    "oracle",
    "ovh",
    "roblox",
    "scaleway",
    "vercel",
    "telegram",
    "all",
]


def convert_ruleset(mihomo_path: Path, source_path: Path, output_path: Path) -> None:
    subprocess.run(
        [
            str(mihomo_path),
            "convert-ruleset",
            "ipcidr",
            "text",
            str(source_path),
            str(output_path),
        ],
        check=True,
        cwd=REPO_ROOT,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate mihomo .mrs ruleset files")
    parser.add_argument(
        "--mihomo", type=Path, default="mihomo", help="Path to mihomo executable"
    )
    args = parser.parse_args()

    for provider in PROVIDERS:
        print(f"Processing {provider}")
        provider_dir = REPO_ROOT / provider
        source_all = provider_dir / f"{provider}_plain.txt"
        source_ipv4 = provider_dir / f"{provider}_plain_ipv4.txt"

        if not source_all.exists():
            raise FileNotFoundError(f"Missing source file: {source_all}")
        if not source_ipv4.exists():
            raise FileNotFoundError(f"Missing source file: {source_ipv4}")

        convert_ruleset(args.mihomo, source_all, provider_dir / f"{provider}.mrs")
        convert_ruleset(
            args.mihomo, source_ipv4, provider_dir / f"{provider}_ipv4.mrs"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
