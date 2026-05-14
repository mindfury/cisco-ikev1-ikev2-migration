#!/usr/bin/env python3
"""
Push IKEv1 VTI + BGP config to the ISR 2911 lab router.

Run after 'tofu apply' in the terraform/ directory.  Reads tofu outputs,
cleans up any previous lab config, and pushes the new pre-migration config.

Usage:
    python3 scripts/push_lab_config.py [--dry-run]
"""

import argparse
import asyncio
import json
import subprocess
import sys
import textwrap

import asyncssh


ROUTER_HOST = "c2911.internal"
ROUTER_USER = "admin"
ROUTER_PASS = "Lab12345!"

TERRAFORM_DIR = "terraform"


def get_tofu_outputs() -> dict:
    result = subprocess.run(
        ["tofu", "output", "-json"],
        cwd=TERRAFORM_DIR,
        capture_output=True,
        text=True,
        check=True,
    )
    raw = json.loads(result.stdout)
    return {k: v["value"] for k, v in raw.items()}


def build_config(out: dict) -> str:
    t1_outside = out["tunnel1_outside_ip"]
    t2_outside = out["tunnel2_outside_ip"]
    t1_cgw     = out["tunnel1_cgw_inside_ip"]
    t2_cgw     = out["tunnel2_cgw_inside_ip"]
    t1_vgw     = out["tunnel1_vgw_inside_ip"]
    t2_vgw     = out["tunnel2_vgw_inside_ip"]
    aws_asn    = out["aws_bgp_asn"]
    ec2_ip     = out["ec2_private_ip"]
    t1_psk     = out.get("tunnel1_psk", "<PSK-SEE-TFVARS>")
    t2_psk     = out.get("tunnel2_psk", "<PSK-SEE-TFVARS>")

    # PSKs are marked sensitive in tofu outputs — read from tfvars if not present
    if t1_psk == "<PSK-SEE-TFVARS>":
        try:
            import re, os
            tfvars = open(os.path.join(TERRAFORM_DIR, "terraform.tfvars")).read()
            m = re.search(r'tunnel1_psk\s*=\s*"([^"]+)"', tfvars)
            if m:
                t1_psk = m.group(1)
            m = re.search(r'tunnel2_psk\s*=\s*"([^"]+)"', tfvars)
            if m:
                t2_psk = m.group(1)
        except FileNotFoundError:
            print("WARNING: terraform.tfvars not found; PSKs will be placeholders")

    config = textwrap.dedent(f"""\
        conf t
        !
        ! ── Cleanup: remove previous lab config ──────────────────────────────
        interface GigabitEthernet0/0
         no crypto map CMAP-AWS
        !
        no crypto map CMAP-AWS 10 ipsec-isakmp
        no crypto map CMAP-AWS 20 ipsec-isakmp
        no crypto ikev2 profile AWS-IKEV2-PROFILE
        no crypto ikev2 keyring AWS-IKEV2-KEYRING
        no crypto ikev2 policy AWS-IKEV2-POLICY
        no crypto ikev2 proposal AWS-IKEV2-PROPOSAL
        no crypto ipsec transform-set TS-AWS-V1
        no ip access-list extended ACL-AWS-VPN
        no router bgp 65000
        !
        ! ── IKEv1 Phase 1 ────────────────────────────────────────────────────
        ! group 2 PFS in ipsec profile will be flagged WEAK by migration tool
        crypto isakmp policy 10
         encr aes 256
         hash sha256
         authentication pre-share
         group 14
         lifetime 28800
        !
        crypto isakmp key {t1_psk} address {t1_outside}
        crypto isakmp key {t2_psk} address {t2_outside}
        !
        ! ── Phase 2 transform-set ────────────────────────────────────────────
        crypto ipsec transform-set TS-AWS-VTI esp-aes 256 esp-sha256-hmac
         mode tunnel
        !
        ! ── IPsec profile — NO ikev2-profile yet (pre-migration state) ───────
        crypto ipsec profile AWS-VTI-PROFILE
         set transform-set TS-AWS-VTI
         set pfs group2
        !
        ! ── Tunnel interfaces ─────────────────────────────────────────────────
        interface Tunnel1
         ip address {t1_cgw} 255.255.255.252
         tunnel source GigabitEthernet0/0
         tunnel mode ipsec ipv4
         tunnel destination {t1_outside}
         tunnel protection ipsec profile AWS-VTI-PROFILE
        !
        interface Tunnel2
         ip address {t2_cgw} 255.255.255.252
         tunnel source GigabitEthernet0/0
         tunnel mode ipsec ipv4
         tunnel destination {t2_outside}
         tunnel protection ipsec profile AWS-VTI-PROFILE
        !
        ! ── BGP ──────────────────────────────────────────────────────────────
        router bgp 65000
         bgp log-neighbor-changes
         neighbor {t1_vgw} remote-as {aws_asn}
         neighbor {t1_vgw} timers 10 30 30
         neighbor {t2_vgw} remote-as {aws_asn}
         neighbor {t2_vgw} timers 10 30 30
         !
         address-family ipv4
          network 10.0.1.0 mask 255.255.255.0
          neighbor {t1_vgw} activate
          neighbor {t1_vgw} soft-reconfiguration inbound
          neighbor {t2_vgw} activate
          neighbor {t2_vgw} soft-reconfiguration inbound
         exit-address-family
        !
        end
        write memory
    """)

    summary = textwrap.dedent(f"""
        ── Lab summary ───────────────────────────────────────────
        Tunnel 1   outside  {t1_outside}
                   cgw-ip   {t1_cgw}/30
                   vgw-ip   {t1_vgw}/30  (BGP neighbor, remote-as {aws_asn})
        Tunnel 2   outside  {t2_outside}
                   cgw-ip   {t2_cgw}/30
                   vgw-ip   {t2_vgw}/30  (BGP neighbor, remote-as {aws_asn})
        EC2 target {ec2_ip}
        ──────────────────────────────────────────────────────────
        Next steps:
          1. Wait ~30s for tunnels to come up
          2. show crypto isakmp sa          → QM_IDLE both peers
          3. show ip bgp summary            → Established both neighbors
          4. ping {ec2_ip} source <LAN-IP> repeat 10
          5. ssh admin@{ROUTER_HOST} "show running-config" > running.cfg
          6. python3 ikev1_to_ikev2_migrate.py --config-file running.cfg --audit-only
          7. python3 ikev1_to_ikev2_migrate.py --config-file running.cfg > ikev2_additions.txt
          8. Review ikev2_additions.txt, then apply via: python3 scripts/apply_migration.py
        ──────────────────────────────────────────────────────────
    """)

    return config, summary


async def push_config(config: str, dry_run: bool):
    if dry_run:
        print("── DRY RUN: config that would be pushed ─────────────────────────")
        print(config)
        return

    print(f"Connecting to {ROUTER_HOST} ...")
    async with asyncssh.connect(
        ROUTER_HOST,
        username=ROUTER_USER,
        password=ROUTER_PASS,
        known_hosts=None,
        kex_algs=["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"],
        server_host_key_algs=["ssh-rsa"],
    ) as conn:
        print("Connected — pushing config ...")
        result = await conn.run(config, check=False)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr, file=sys.stderr)
        print("Done.")


async def verify(out: dict):
    print("\nVerifying ...")
    checks = [
        "show crypto isakmp sa",
        "show ip bgp summary",
        f"ping {out['ec2_private_ip']} source 10.0.1.1 repeat 5",
    ]
    async with asyncssh.connect(
        ROUTER_HOST,
        username=ROUTER_USER,
        password=ROUTER_PASS,
        known_hosts=None,
        kex_algs=["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"],
        server_host_key_algs=["ssh-rsa"],
    ) as conn:
        for cmd in checks:
            print(f"\n── {cmd} ──")
            r = await conn.run(cmd, check=False)
            print(r.stdout or "(no output)")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="Print config without pushing")
    ap.add_argument("--verify", action="store_true", help="Run verification checks after push")
    ap.add_argument("--verify-only", action="store_true", help="Run verification checks only (skip push)")
    args = ap.parse_args()

    print("Reading tofu outputs ...")
    try:
        out = get_tofu_outputs()
    except subprocess.CalledProcessError as e:
        print(f"ERROR: tofu output failed — have you run 'tofu apply' in {TERRAFORM_DIR}/?")
        print(e.stderr)
        sys.exit(1)

    config, summary = build_config(out)

    if not args.verify_only:
        asyncio.run(push_config(config, dry_run=args.dry_run))
        print(summary)

    if args.verify or args.verify_only:
        asyncio.run(verify(out))


if __name__ == "__main__":
    main()
