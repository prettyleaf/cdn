#!/usr/bin/env python3
"""Generate Mihomo .mrs rule-provider files from plain text lists."""
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
    "discord",
    "fastly",
    "hetzner",
    "oracle",
    "ovh",
    "roblox",
    "scaleway",
    "vercel",
    "telegram",
    "all",
]


def convert_ruleset(
    mihomo_path: Path, behavior: str, source_path: Path, output_path: Path
) -> None:
    subprocess.run(
        [
            str(mihomo_path),
            "convert-ruleset",
            behavior,
            "text",
            str(source_path),
            str(output_path),
        ],
        check=True,
        cwd=REPO_ROOT,
    )


def generate_provider_rulesets(mihomo_path: Path, provider: str) -> None:
    provider_dir = REPO_ROOT / provider

    plain_path = provider_dir / f"{provider}_plain.txt"
    plain_ipv4_path = provider_dir / f"{provider}_plain_ipv4.txt"
    domains_path = provider_dir / f"{provider}_domains.txt"

    if not plain_path.exists():
        raise FileNotFoundError(f"Missing source file: {plain_path}")
    if not plain_ipv4_path.exists():
        raise FileNotFoundError(f"Missing source file: {plain_ipv4_path}")

    convert_ruleset(
        mihomo_path,
        "ipcidr",
        plain_path,
        provider_dir / f"{provider}_mihomo.mrs",
    )
    convert_ruleset(
        mihomo_path,
        "ipcidr",
        plain_ipv4_path,
        provider_dir / f"{provider}_mihomo_ipv4.mrs",
    )

    if domains_path.exists() and any(
        line.strip() for line in domains_path.read_text(encoding="utf-8").splitlines()
    ):
        convert_ruleset(
            mihomo_path,
            "domain",
            domains_path,
            provider_dir / f"{provider}_mihomo_domains.mrs",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Mihomo .mrs ruleset files")
    parser.add_argument(
        "--mihomo", type=Path, default="mihomo", help="Path to mihomo executable"
    )
    args = parser.parse_args()

    for provider in PROVIDERS:
        print(f"Processing {provider}")
        generate_provider_rulesets(args.mihomo, provider)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
