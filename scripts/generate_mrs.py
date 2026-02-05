#!/usr/bin/env python3
"""Generate Mihomo MRS (Meta Rule Set) files from existing CDN IP lists.

MRS is a binary format used by Mihomo (MetaCubeX) for efficient rule providers.
This script converts plain text IP lists to MRS format using the mihomo CLI tool.

Usage:
    python generate_mrs.py

Requirements:
    - mihomo CLI tool must be installed and available in PATH
    - Download from: https://github.com/MetaCubeX/mihomo/releases
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
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
    "hetzner",
    "oracle",
    "ovh",
    "roblox",
    "scaleway",
    "vercel",
    "all",
]


def check_mihomo_installed() -> bool:
    """Check if mihomo CLI is available in PATH."""
    try:
        # Try to invoke mihomo with a harmless flag to ensure it is installed and executable
        subprocess.run(
            ["mihomo", "-v"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except FileNotFoundError:
        return False
    except Exception:
        # Any unexpected error while invoking mihomo is treated as not installed/usable
        return False


def convert_to_mrs(source_path: Path, output_path: Path, behavior: str = "ipcidr") -> bool:
    """Convert a text file to MRS format using mihomo CLI.
    
    Args:
        source_path: Path to the source text file with IP ranges
        output_path: Path where the MRS file will be created
        behavior: Rule behavior type - 'ipcidr' for IP ranges, 'domain' for domains
        
    Returns:
        True if conversion succeeded, False otherwise
    """
    try:
        subprocess.run(
            [
                "mihomo",
                "convert-ruleset",
                behavior,
                "text",
                str(source_path),
                str(output_path),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return True
    except subprocess.CalledProcessError as exc:
        print(f"  Error converting {source_path.name}: {exc.stderr}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print("  Error: mihomo command not found", file=sys.stderr)
        return False


def generate_mrs_for_provider(provider: str) -> tuple[int, int]:
    """Generate MRS files for a single provider.
    
    Args:
        provider: Name of the CDN provider
        
    Returns:
        Tuple of (success_count, failure_count)
    """
    provider_dir = REPO_ROOT / provider
    success_count = 0
    failure_count = 0
    
    # Convert plain.txt (all IPs including IPv6)
    plain_path = provider_dir / f"{provider}_plain.txt"
    if plain_path.exists():
        mrs_path = provider_dir / f"{provider}_ipcidr.mrs"
        if convert_to_mrs(plain_path, mrs_path):
            success_count += 1
        else:
            failure_count += 1
    
    # Convert plain_ipv4.txt (IPv4 only)
    plain_ipv4_path = provider_dir / f"{provider}_plain_ipv4.txt"
    if plain_ipv4_path.exists():
        mrs_ipv4_path = provider_dir / f"{provider}_ipcidr_ipv4.mrs"
        if convert_to_mrs(plain_ipv4_path, mrs_ipv4_path):
            success_count += 1
        else:
            failure_count += 1
    
    return success_count, failure_count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Mihomo MRS files for CDN IP lists."
    )
    parser.add_argument(
        "--provider",
        choices=PROVIDERS,
        help="Generate MRS for a specific provider only",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check if mihomo is installed and exit",
    )
    args = parser.parse_args()

    if args.check:
        if check_mihomo_installed():
            print("mihomo CLI is installed and available")
            return 0
        else:
            print("mihomo CLI is NOT installed or not in PATH", file=sys.stderr)
            print("Download from: https://github.com/MetaCubeX/mihomo/releases", file=sys.stderr)
            return 1

    if not check_mihomo_installed():
        print("Error: mihomo CLI is not installed or not in PATH", file=sys.stderr)
        print("Download from: https://github.com/MetaCubeX/mihomo/releases", file=sys.stderr)
        print("\nTo install on various platforms:", file=sys.stderr)
        print("  - Download the appropriate binary from the releases page", file=sys.stderr)
        print("  - Extract and add to your PATH", file=sys.stderr)
        return 1

    providers_to_process = [args.provider] if args.provider else PROVIDERS
    total_success = 0
    total_failure = 0

    print("Generating MRS files...")
    print("-" * 50)

    for provider in providers_to_process:
        provider_dir = REPO_ROOT / provider
        if not provider_dir.exists():
            print(f"Skipping {provider}: directory not found")
            continue

        success, failure = generate_mrs_for_provider(provider)
        total_success += success
        total_failure += failure
        
        if success > 0:
            print(f"Generated {success} MRS file(s) for {provider}")
        if failure > 0:
            print(f"Failed to generate {failure} MRS file(s) for {provider}", file=sys.stderr)

    print("-" * 50)
    print(f"Total: {total_success} succeeded, {total_failure} failed")

    return 1 if total_failure > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
