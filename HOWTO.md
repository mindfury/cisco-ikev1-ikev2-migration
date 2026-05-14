# IKEv1 → IKEv2 Migration Tool — HOWTO

**Target platform:** Cisco ISR4431, IOS XE 17.09.05a  
**Migration driver:** Field Notice FN72510 — weak crypto algorithms blocked in IOS XE 17.11+  
**Validation status:** IKEv2 policy-based (crypto map) validated end-to-end on ISR 4431 / IOS XE 17.09.05a against a live AWS VGW. IKEv1 VTI/BGP baseline validated on ISR 2911 / IOS 15.7(3)M3 in a NAT'd home lab. IKEv2 VTI/BGP requires IOS XE and has not yet been validated end-to-end.

---

## Table of Contents

1. [Background](#1-background)
2. [How the Migration Works](#2-how-the-migration-works)
3. [Prerequisites](#3-prerequisites)
4. [AWS Side: Verifying and Preparing the VPN Connection](#4-aws-side-verifying-and-preparing-the-vpn-connection)
5. [Pre-Migration Checklist](#5-pre-migration-checklist)
6. [File Mode: Policy-Based (Crypto Map)](#6-file-mode-policy-based-crypto-map)
7. [File Mode: Route-Based (VTI + BGP)](#7-file-mode-route-based-vti--bgp)
8. [Reviewing the Generated Config](#8-reviewing-the-generated-config)
9. [Applying the Config](#9-applying-the-config)
10. [Validation](#10-validation)
11. [Rollback](#11-rollback)
12. [Device Mode (RESTCONF) — Advanced](#12-device-mode-restconf--advanced)
13. [Algorithm Reference](#13-algorithm-reference)
14. [Known Limitations](#14-known-limitations)
15. [Troubleshooting](#15-troubleshooting)
16. [Lab Environment (OpenTofu/Terraform)](#16-lab-environment-opentofuterraform)

---

## 1. Background

### The Problem

Cisco IOS XE 17.11 and later enforce **FN72510**, blocking IPsec negotiation using weak cryptographic primitives:

| Blocked | FN72510 reason |
|---|---|
| DES, 3DES encryption | Cryptographically broken |
| MD5 HMAC | Collision-vulnerable |
| DH groups 1, 2, 5, 24 | Insufficient key size |

If your device runs AWS Site-to-Site VPN tunnels with any of these algorithms (common in pre-2020 configurations), **those tunnels will drop on the first IKE renegotiation after upgrading to 17.11+**.

### The Strategy

This tool performs an **additive migration**:

1. IKEv1 objects are **left completely untouched** — the old config remains valid
2. New IKEv2 objects are added alongside: proposal, policy, keyring, profile, and upgraded transform-sets
3. The activation switch is a single line on each crypto map entry: `set ikev2-profile <name>`
4. **Rollback** is `no set ikev2-profile` — IKEv1 resumes immediately

This means you can test IKEv2 in production, confirm the tunnels are healthy, and only then upgrade IOS XE. If anything is wrong, a one-line rollback restores the original state.

---

## 2. How the Migration Works

The tool handles two VPN architectures. Both produce ready-to-paste CLI blocks.

### Policy-based VPN (crypto map)

```
IKEv1 config (show run)
        │
        ▼
  ConfigParser
        │  parses: isakmp policies, PSKs, transform-sets, crypto map entries
        │
        ▼
  IKEv2ConfigGenerator
        │  generates:
        │    - crypto ikev2 proposal   (AES-CBC-256 / SHA-512 / DH group 21)
        │    - crypto ikev2 policy     (matches any fvrf)
        │    - crypto ikev2 keyring    (one peer entry per tunnel endpoint)
        │    - crypto ikev2 profile    (PSK auth, DPD 10/3 periodic, 28800s lifetime)
        │    - crypto ipsec transform-set *-V2  (esp-aes 256 esp-sha512-hmac, only if old TS is weak)
        │    - crypto map updates      (set ikev2-profile + pfs group21 on each entry)
        │
        ▼
  Ready-to-paste CLI block (or RESTCONF PATCH payload in device mode)
```

A crypto map entry is targeted if it is `ipsec-isakmp` type and does **not** already have `set ikev2-profile`. Entries already migrated are skipped.

### Route-based VPN (VTI + BGP)

```
IKEv1 config (show run)
        │
        ▼
  ConfigParser
        │  parses: isakmp policies, PSKs, transform-sets,
        │          crypto ipsec profiles, Tunnel interfaces,
        │          BGP neighbors
        │
        ▼
  IKEv2ConfigGenerator
        │  generates:
        │    - crypto ikev2 proposal / policy / keyring / profile  (same as above)
        │    - crypto ipsec profile updates:
        │        set transform-set <upgraded-TS>
        │        set pfs group21
        │        set ikev2-profile AWS-IKEV2-PROFILE
        │    - NOTE: tunnel interfaces and BGP are NOT modified
        │
        ▼
  Ready-to-paste CLI block
```

Tunnel interface addresses, sources, and destinations are preserved. BGP neighbors running over the tunnel inside IPs continue operating without change — BGP is independent of the IKE version.

### IKEv1 and IKEv2 coexistence

IKEv1 and IKEv2 can coexist on the same router and the same UDP 500/4500 ports. Every IKE packet header carries a Major Version field (1 or 2); IOS XE maintains separate SA databases for each. This means:

- You can apply the IKEv2 config without clearing existing IKEv1 SAs
- Tunnels migrate one at a time as IKEv1 SAs expire and renegotiate
- The `set ikev2-profile` line is the only activation switch — add it to go IKEv2, remove it to revert to IKEv1

---

## 3. Prerequisites

### Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt   # requests, netmiko, asyncssh
```

### What you need before running

- A text copy of the device's `show running-config` output (file mode), **or** RESTCONF credentials (device mode)
- The AWS VPN configuration download for your VPN connection (from the AWS Console — needed to verify PSK values)
- A maintenance window (applying the config is non-disruptive, but the first IKEv2 negotiation will briefly interrupt traffic on each tunnel as SAs are renegotiated)

---

## 4. AWS Side: Verifying and Preparing the VPN Connection

### Does AWS already support IKEv2?

Yes. AWS Site-to-Site VPN has supported IKEv2 since 2019. No AWS-side changes are required to migrate from IKEv1 to IKEv2 on an existing VPN connection, **unless** the connection was explicitly created with `IKEVersions: [v1]` only.

To check in the AWS Console:

1. **VPC → Site-to-Site VPN Connections** → select your VPN
2. **Tunnel details** tab → check "IKE versions" for each tunnel
3. If it shows `ikev1` only, you need to modify the tunnel options (see below)

To check or update via CLI/boto3:

```python
import boto3

ec2 = boto3.client("ec2", region_name="us-east-1")

# Check current IKE versions
vpn = ec2.describe_vpn_connections(
    Filters=[{"Name": "tag:Name", "Values": ["your-vpn-name"]}]
)["VpnConnections"][0]

for t in vpn["Options"]["TunnelOptions"]:
    print(t["OutsideIpAddress"], "→ IKE versions:", t.get("IKEVersions", "not set (default: both)"))
```

If the tunnel options don't restrict IKE versions, AWS will accept whichever version the customer gateway initiates. Your router initiating IKEv2 is enough.

### To explicitly enable IKEv2 on a tunnel

```python
ec2.modify_vpn_tunnel_options(
    VpnConnectionId="vpn-xxxxxxxx",
    VpnTunnelOutsideIpAddress="3.x.x.x",   # tunnel 1 AWS endpoint
    TunnelOptions={
        "IKEVersions": [{"Value": "ikev2"}],   # or [{"Value": "ikev1"}, {"Value": "ikev2"}]
        "Phase1EncryptionAlgorithms": [{"Value": "AES256"}],
        "Phase1IntegrityAlgorithms":  [{"Value": "SHA2-512"}],
        "Phase1DHGroupNumbers":       [{"Value": 21}],
        "Phase2EncryptionAlgorithms": [{"Value": "AES256"}],
        "Phase2IntegrityAlgorithms":  [{"Value": "SHA2-512"}],
        "Phase2DHGroupNumbers":       [{"Value": 21}],
        "IKEPreSharedKey":            "<your-psk>",
    }
)
```

> **Note:** Modifying tunnel options tears down the existing IKE SA for that tunnel. AWS brings two tunnels per VPN connection for exactly this reason — modify one at a time.

### Getting the PSK values

The PSK for each tunnel is shown in the **AWS VPN configuration download**:

1. AWS Console → Site-to-Site VPN Connections → select connection
2. **Download configuration** → Vendor: Cisco, Platform: IOS/IOS XE
3. In the downloaded file, each tunnel section contains:
   ```
   Pre-Shared Key   : <value>
   ```

There are **two tunnels, each with its own PSK**. These PSKs are what should appear in your `crypto isakmp key` lines on the router. If your current IKEv1 config has them correct (tunnels are up), those same values go into the IKEv2 keyring.

### PSK symmetry in AWS VPN

For standard AWS Site-to-Site VPN, the PSK is **the same on both sides** of a given tunnel. You do not need to configure different local vs remote keys for AWS. The tool sets both `pre-shared-key local` and `pre-shared-key remote` to the same value extracted from the IKEv1 config — this is correct for AWS.

The only case where you need asymmetric PSKs (`local` ≠ `remote`) is if AWS was explicitly configured that way, which is non-default and would have required a custom IKEv2 tunnel option at creation time.

### AWS VPC routing

Verify the VPC route table has a propagated or static route sending your on-premises subnet(s) back through the VGW:

```
Destination     Target
10.0.0.0/8      vgw-xxxxxxxx     ← your on-prem subnets via VGW
```

Route propagation should handle this automatically if enabled on the route table associated with your VPC subnets.

---

## 5. Pre-Migration Checklist

Work through this before generating or applying any config.

**On the router:**

- [ ] `show crypto isakmp sa` — confirm existing IKEv1 SAs are ACTIVE (QM_IDLE)
- [ ] `show crypto ipsec sa | include encaps|decaps` — confirm bidirectional traffic is flowing
- [ ] `show version` — confirm IOS XE version and platform (IKEv2 VTI requires IOS XE — see Known Limitations)
- [ ] `show crypto engine accelerator statistic` — note current crypto engine load
- [ ] Copy `show running-config` to a file — this is the input to the tool
- [ ] **Policy-based:** Confirm `crypto map <name>` is applied to the correct WAN interface(s)
- [ ] **Route-based VTI:** Confirm `interface TunnelX / tunnel protection ipsec profile <name>` is present; confirm `router bgp` neighbors are Established (`show ip bgp summary`)
- [ ] **Route-based VTI with BGP prefix advertisement:** Confirm the advertised network prefix (`network X.X.X.X mask Y.Y.Y.Y`) has an exact match in the routing table — `show ip route X.X.X.X`. If the router announces a /24 but only has a /32 loopback, add a null route: `ip route X.X.X.0 255.255.255.0 Null0`

**In AWS:**

- [ ] Confirm both VPN tunnels show "UP" in the AWS Console (Tunnel status)
- [ ] Download the VPN configuration file and locate the PSK for each tunnel
- [ ] Cross-check PSKs in the router config against the AWS download — they must match
- [ ] Note the outside IP addresses for both tunnels (you'll need these to verify the keyring)

**General:**

- [ ] Schedule a maintenance window — the first IKEv2 renegotiation will briefly interrupt each tunnel
- [ ] Have console access available as a fallback (especially if managing the router over a VPN itself)
- [ ] Know the rollback command: `no set ikev2-profile <profile-name>` on each crypto map entry

---

## 6. File Mode: Policy-Based (Crypto Map)

### Step 1 — Capture the running config

```bash
ssh admin@<router-ip> "show running-config" > running.cfg
```

### Step 2 — Run the audit

```bash
python3 ikev1_to_ikev2_migrate.py --config-file running.cfg --audit-only
```

Expected output for a typical pre-FN72510 config:

```
! IKEv1 ISAKMP policies found: 1
!   Policy 10: enc=3des hash=md5 group=2  *** WEAK-ENC:3des, WEAK-HASH:md5, WEAK-GROUP:2
!
! IKEv1 pre-shared keys: 2
!   Peer 1.2.3.4
!   Peer 5.6.7.8
!
! Transform-sets: 1
!   TS-AWS-WEAK: esp-3des esp-md5-hmac *** WEAK
!
! Crypto map entries targeted for migration: 2
!   CMAP-AWS seq 10: peer=1.2.3.4 ts=['TS-AWS-WEAK'] pfs=group2
!   CMAP-AWS seq 20: peer=5.6.7.8 ts=['TS-AWS-WEAK'] pfs=group2
```

For a config where AWS defaults were used (AES-128/SHA1 are implicit defaults, not shown in `show run`):

```
! Policy 10: enc=aes hash=sha group=2  *** WEAK-GROUP:2
```

`enc=aes` and `hash=sha` are the IOS defaults when those lines are absent from the config. Group 2 is also the default and is the only algorithm that needs remediation in this case.

### Step 3 — Generate the IKEv2 config additions

```bash
python3 ikev1_to_ikev2_migrate.py --config-file running.cfg > ikev2_additions.txt
cat ikev2_additions.txt
```

### Step 4 — Review and edit before applying

See [Section 8](#8-reviewing-the-generated-config) for what to check.

### Step 5 — Apply and validate

See [Section 9](#9-applying-the-config) and [Section 10](#10-validation).

---

## 7. File Mode: Route-Based (VTI + BGP)

Use this section if your VPN uses VTI tunnel interfaces with BGP (the route-based model common in newer AWS Site-to-Site VPN connections). The tool auto-detects which model is in use based on the presence of `interface Tunnel` + `tunnel protection ipsec profile` lines.

### VTI/BGP migration overview

```
IKEv1 (before)                     IKEv2 (after)
─────────────────────────────────   ──────────────────────────────────────
crypto isakmp policy 10              crypto ikev2 proposal AWS-IKEV2-PROPOSAL
 encr aes 256                         encryption aes-cbc-256
 hash sha256                          integrity sha512
 group 14                             prf sha512
                                      group twenty-one

crypto isakmp key PSK1 addr X.X.X.X  crypto ikev2 keyring AWS-IKEV2-KEYRING
crypto isakmp key PSK2 addr Y.Y.Y.Y   peer PEER-X-X-X-X
                                        address X.X.X.X
                                        pre-shared-key local PSK1
                                        pre-shared-key remote PSK1
                                       peer PEER-Y-Y-Y-Y
                                        address Y.Y.Y.Y
                                        pre-shared-key local PSK2
                                        pre-shared-key remote PSK2

                                      crypto ikev2 profile AWS-IKEV2-PROFILE
                                       match identity remote address 0.0.0.0
                                       authentication remote pre-share
                                       authentication local pre-share
                                       keyring local AWS-IKEV2-KEYRING
                                       dpd 10 3 periodic

crypto ipsec profile AWS-VTI-PROFILE  crypto ipsec profile AWS-VTI-PROFILE
 set transform-set TS-VTI              set transform-set TS-VTI-V2   ← upgraded
 set pfs group2                        set pfs group21               ← upgraded
                                       set ikev2-profile AWS-IKEV2-PROFILE  ← NEW

interface Tunnel1                     interface Tunnel1
 ip address 169.254.x.y/30             (unchanged)
 tunnel source GigEth0/0
 tunnel destination X.X.X.X
 tunnel protection ipsec profile …

router bgp 65000                      router bgp 65000
 neighbor 169.254.x.x remote-as …     (unchanged)
```

### Step 1 — Verify BGP null route (if applicable)

If your BGP `network` statement advertises a prefix that exists only as a loopback /32, you need a static null route to create the exact prefix in the routing table:

```
! Example: Loopback0 = 10.0.1.1/32, BGP network = 10.0.1.0/24
ip route 10.0.1.0 255.255.255.0 Null0
```

Without this, the BGP `network` command silently fails to advertise the prefix and EC2 has no return path.

Verify:
```
show ip route 10.0.1.0
show ip bgp 10.0.1.0
```

Both should exist before proceeding.

### Step 2 — Capture and audit

```bash
ssh admin@<router-ip> "show running-config" > running.cfg
python3 ikev1_to_ikev2_migrate.py --config-file running.cfg --audit-only
```

Expected audit output for a VTI/BGP config:

```
! IKEv1 ISAKMP policies found: 1
!   Policy 10: enc=aes 256 hash=sha256 group=14  *** WEAK-GROUP:14 (group21 preferred)
!
! IKEv1 pre-shared keys: 2
!   Peer 35.169.156.239
!   Peer 50.19.54.34
!
! IPsec profiles (VTI mode): 2
!   AWS-VTI-PROFILE → transform-set TS-VTI, pfs group2  *** WEAK-PFS
!
! BGP neighbors detected (will not be modified):
!   169.254.107.57 (remote-as 64512)
!   169.254.16.113 (remote-as 64512)
```

### Step 3 — Generate and review

```bash
python3 ikev1_to_ikev2_migrate.py --config-file running.cfg > ikev2_additions.txt
cat ikev2_additions.txt
```

The output will contain new IKEv2 objects plus updated `crypto ipsec profile` blocks. Tunnel interfaces and BGP will not appear — they are not modified.

### Step 4 — Review generated config

See [Section 8](#8-reviewing-the-generated-config) for common checks. Additional VTI-specific checks:

- Keyring peer IPs must match the AWS VGW **outside** IP addresses (the `tunnel destination` values in the Tunnel interfaces)
- The ipsec profile update adds `set ikev2-profile` — confirm the profile name matches what is referenced in the Tunnel interfaces (`tunnel protection ipsec profile <name>`)
- The transform-set name will be `<original-name>-V2` if the original was weak — confirm the ipsec profile references this new name

### Step 5 — Apply and validate

See [Section 9](#9-applying-the-config) and [Section 10](#10-validation).

**VTI-specific validation:**

```
! IKEv2 SAs — expect READY for both tunnel endpoints
show crypto ikev2 sa

! IPsec SAs — expect inbound/outbound ESP active
show crypto ipsec sa | include peer|encaps|decaps

! Tunnel line protocol — expect both up
show interfaces Tunnel1 | include line protocol
show interfaces Tunnel2 | include line protocol

! BGP — expect Established, 1 prefix received per neighbor
show ip bgp summary

! Ping through the tunnel
ping <ec2-ip> source <loopback-or-lan-ip> repeat 10
```

---

## 8. Reviewing the Generated Config

**Never paste the generated config directly without reviewing these items:**

### 8.1 PSK values

The keyring will contain PSKs copied from your `crypto isakmp key` lines:

```
crypto ikev2 keyring AWS-IKEV2-KEYRING
 peer PEER-1-2-3-4
  address 1.2.3.4
  pre-shared-key local TestPSK
  pre-shared-key remote TestPSK
```

Verify against the AWS VPN configuration download:
- Are these the PSKs AWS expects?
- If the IOS config stored them as type 6 encrypted (`key 6 <blob>`), the tool will output `<PSK_TYPE6_ENCRYPTED_REPLACE_ME>` — you must substitute the plaintext value

### 8.2 Peer IP addresses

Confirm the peer addresses in the keyring match the **AWS VGW outside IP addresses** from the VPN configuration download. These are the addresses you already have in your `crypto isakmp key` and `set peer` lines.

### 8.3 Transform-set selection

- If the existing transform-set was weak (3DES/MD5), the tool creates a `*-V2` replacement using `esp-aes 256 esp-sha512-hmac` — confirm this combination is supported on your platform (confirmed available on ISR4431/17.09.05a)
- If the existing transform-set was already acceptable (e.g., `esp-aes esp-sha-hmac`), the tool keeps the original name and only adds `set ikev2-profile` and upgrades PFS

### 8.4 The `identity local address` placeholder

```
crypto ikev2 profile AWS-IKEV2-PROFILE
 match identity remote address 0.0.0.0
 ! identity local address <YOUR-WAN-INTERFACE-IP>
```

The commented-out `identity local address` line is intentionally left for you to decide:
- If your WAN interface has a static public IP directly on the router, add: `identity local address <your-public-ip>`
- If the router is behind NAT (unlikely for an ISR4431 in a typical datacenter/branch setup, but possible), the identity will default to the interface IP. NAT-T will handle the NAT traversal automatically — `identity local address` is still beneficial to explicitly set for AWS identity matching
- If omitted, the device uses its WAN interface IP as its IKEv2 identity — this works for most deployments

### 8.5 Profile match scope

```
 match identity remote address 0.0.0.0
```

This matches **any** IKEv2 peer, relying on the keyring to enforce peer-specific PSKs. This is correct for an AWS VPN configuration where both tunnel endpoints should use this profile. If you have other IKEv2 peers on the device that should use a different profile, narrow the match:

```
 match identity remote address 1.2.3.4 255.255.255.255
 match identity remote address 5.6.7.8 255.255.255.255
```

### 8.6 SA lifetime

The generated profile uses `lifetime 28800` (8 hours) to match AWS's IKEv2 default. AWS will also send its preferred lifetime in the IKE_SA_INIT; the lower of the two will be used. Do not shorten this without understanding the AWS DPD and rekey behaviour.

---

## 9. Applying the Config

### In a maintenance window

```
! 1. Paste the generated config block
conf t
<paste ikev2_additions.txt content here>
end

! 2. Verify it took
show crypto ikev2 proposal AWS-IKEV2-PROPOSAL
show crypto ikev2 policy AWS-IKEV2-POLICY
show crypto ikev2 profile AWS-IKEV2-PROFILE
show crypto map | include ikev2

! 3. Clear existing IKEv1 SAs to trigger renegotiation as IKEv2
clear crypto isakmp
clear crypto sa

! 4. Traffic will trigger IKEv2 SA establishment
! AWS initiates keepalives — tunnels should come up within 30s without traffic
```

> **Warning:** `clear crypto sa` drops all active IPsec SAs immediately. If the router is the only path between your network and AWS, existing TCP sessions through the tunnel will be interrupted. Plan accordingly.

### If you cannot `clear crypto sa` in production

Omit the clear commands. The IKEv1 SAs will remain active until they expire naturally (IKE lifetime / IPsec lifetime). Once they expire, the next renegotiation will use IKEv2 because `set ikev2-profile` is now configured. This is the zero-disruption approach — tunnels migrate tunnel by tunnel as each SA expires.

### Save the config

```
write memory
```

---

## 10. Validation

After applying and triggering renegotiation:

```
! IKEv2 SA should be READY
show crypto ikev2 sa

! Expected output:
! Tunnel-id Local               Remote              fvrf/ivrf   Status
! 1         10.0.0.1/4500       1.2.3.4/4500        none/none   READY
!       Encr: AES-CBC, keysize: 256, PRF: SHA512, Hash: SHA512, DH Grp:21, Auth sign: PSK, Auth verify: PSK
!       Life/Active Time: 28800/xx sec

! IKEv1 SA should be empty (or show deleted state)
show crypto isakmp sa

! IPsec packet counters should be incrementing bidirectionally
show crypto ipsec sa | include encaps|decaps

! Ping through the tunnel from the router itself (substitute your VPC subnet/host)
ping 10.10.1.1 source Loopback0 repeat 5
```

In AWS Console:
- **VPC → Site-to-Site VPN Connections → Tunnel details**: both tunnels should show **"UP"**
- The "Last status change" timestamp will reflect the IKEv2 renegotiation

---

## 11. Rollback

### Policy-based (crypto map) rollback

```
conf t
crypto map CMAP-AWS 10 ipsec-isakmp
 no set ikev2-profile AWS-IKEV2-PROFILE
!
crypto map CMAP-AWS 20 ipsec-isakmp
 no set ikev2-profile AWS-IKEV2-PROFILE
!
end
clear crypto isakmp
clear crypto sa
write memory
```

### Route-based (VTI) rollback

```
conf t
crypto ipsec profile AWS-VTI-PROFILE
 no set ikev2-profile AWS-IKEV2-PROFILE
 set transform-set TS-VTI          ! restore original transform-set name
 set pfs group2                    ! restore original PFS (or whatever was there)
!
end
clear crypto session
write memory
```

In both cases, the IKEv2 objects (proposal, policy, keyring, profile) remain in the config but are inert without a binding. Once you've resolved the issue, remove them:

```
conf t
no crypto ikev2 profile AWS-IKEV2-PROFILE
no crypto ikev2 keyring AWS-IKEV2-KEYRING
no crypto ikev2 policy AWS-IKEV2-POLICY
no crypto ikev2 proposal AWS-IKEV2-PROPOSAL
! Also remove -V2 transform-sets if they were created
no crypto ipsec transform-set TS-VTI-V2
end
write memory
```

---

## 12. Device Mode (RESTCONF) — Advanced

> **Status:** Structurally complete and tested for correctness against the Cisco IOS XE YANG model. End-to-end PATCH against a live ISR4431 has not been validated. Use file mode for the first production run.

Device mode automates the full cycle: GET config → parse → generate → PATCH back → validate.

```bash
# Dry run first — shows what would be PATCHed without touching the device
python3 ikev1_to_ikev2_migrate.py \
  --device 192.0.2.1 \
  --username admin \
  --password <password> \
  --no-verify-ssl \
  --dry-run

# Full run with audit then apply
python3 ikev1_to_ikev2_migrate.py \
  --device 192.0.2.1 \
  --username admin \
  --password <password> \
  --no-verify-ssl \
  --aws-peer 1.2.3.4    # optional: restrict to one peer
```

### RESTCONF prerequisites on IOS XE

```
ip http server
ip http secure-server
ip http authentication local
restconf
```

Verify RESTCONF is responding:

```bash
curl -sk -u admin:password \
  https://192.0.2.1/restconf/data/Cisco-IOS-XE-native:native/hostname \
  -H "Accept: application/yang-data+json"
```

### YANG model notes

- Tested against `Cisco-IOS-XE-crypto` revision 2023-07-01
- IKEv2 proposal group names use spelled-out English: `"twenty-one"` not `"21"`
- Type-empty YANG leaves encode as `[null]` in JSON (Python `[None]`)
- PATCH merges at the path level — existing objects with the same name are updated, others untouched

### Encrypted PSK caveat

If PSKs are stored as type 6 (`password encryption aes` / `key config-key`), RESTCONF returns them encrypted. The tool detects this and emits a `<PSK_TYPE6_ENCRYPTED_REPLACE_ME>` placeholder in the keyring. The PATCH will fail or create a non-functional keyring if you proceed without substituting the actual plaintext PSK.

Solution: temporarily enable type 0 for the migration, or manually edit the generated payload/config before applying.

---

## 13. Algorithm Reference

### IKEv2 Proposal (Phase 1)

| Parameter | Value | Notes |
|---|---|---|
| Encryption | `aes-cbc-256` | AES-GCM unavailable on ISR4431/17.09.05a |
| Integrity | `sha512` | Required with CBC; not needed with GCM |
| PRF | `sha512` | |
| DH Group | `21` | 521-bit ECP; highest available on this image |

### IPsec Transform-Set (Phase 2)

| Parameter | Value |
|---|---|
| ESP encryption | `esp-aes 256` |
| ESP integrity | `esp-sha512-hmac` |
| PFS | `group21` |

### IKEv1 algorithms blocked by FN72510 (never use post-17.11)

| Type | Blocked values |
|---|---|
| Encryption | DES, 3DES |
| Hash / integrity | MD5 |
| DH / PFS groups | 1, 2, 5, 24 |

### AWS VGW supported IKEv2 algorithms (reference)

Phase 1: AES128-CBC, AES256-CBC, AES128-GCM-16, AES256-GCM-16 / SHA1, SHA2-256, SHA2-384, SHA2-512 / DH groups 2, 14–21, 22–24

Phase 2: Same encryption options / SHA1, SHA2-256, SHA2-384, SHA2-512 / PFS groups 2, 5, 14–21, 22–24

All values used by this tool fall within the AWS-supported set.

---

## 14. Known Limitations

### PSK type 6 encryption

If your router uses `password encryption aes` (type 6), PSKs in `show running-config` appear as encrypted blobs. The tool cannot decrypt these. You must supply plaintext PSK values manually in the generated keyring.

### Multiple peers sharing one crypto map

If multiple `set peer` entries exist on a single crypto map entry (primary + backup), the tool captures only the primary peer from the `set peer` line. Verify the keyring covers all peers the map may use.

### Non-AWS IKEv2 peers

The tool generates a single `AWS-IKEV2-PROFILE` that matches all remote addresses. If the device has non-AWS IKEv2 peers that need different authentication or algorithms, you must either:
- Narrow the `match identity remote address` in the generated profile, or
- Create separate profiles and assign them to the appropriate crypto map entries

### Classic IOS (non-XE) — file mode only

File mode works on classic IOS (15.x) — the generated config is valid IOS syntax. Device mode requires IOS XE (RESTCONF is IOS XE only). The ISR 2911 used for lab testing runs classic IOS 15.7 and was managed entirely in file mode.

### IOS 15.7 (classic IOS, C2900) cannot initiate IKEv2 for VTI tunnels

IOS 15.7(3)M3 on an ISR 2911 does NOT initiate IKEv2 when `set ikev2-profile` is configured under a `crypto ipsec profile` bound to a VTI tunnel. Even with an IKEv1 ISAKMP policy removed (forcing IKEv2 as the only option), zero IKEv2 SA activity is observed — the tunnels simply go down with no initiation attempt.

This is a platform limitation of classic IOS on C2900 hardware. The tool generates correct IKEv2 config that works on IOS XE. For lab validation of VTI/BGP IKEv2, use an ISR4431, CSR1000v, or Cat8000v (any IOS XE platform).

**IKEv1 VTI/BGP on IOS 15.7 was fully validated** (tunnels up, BGP established, traffic flowing). Only the IKEv2 side requires IOS XE.

### AWS Phase 2 algorithm restrictions cause PROPOSAL_NOT_CHOSEN

Setting Phase 2 (IPsec/ESP) algorithm restrictions on an AWS VPN connection — `Phase2EncryptionAlgorithms`, `Phase2IntegrityAlgorithms`, or `Phase2DHGroupNumbers` — causes AWS to immediately reject IKEv1 Phase 2 (Quick Mode) proposals with `PROPOSAL_NOT_CHOSEN` unless your router's transform-set and PFS group match exactly.

The default behavior (no Phase 2 restrictions) allows AWS to accept a broad range of proposals. **Do not add Phase 2 restrictions unless you have verified exact algorithm alignment.** If you added them and are seeing `PROPOSAL_NOT_CHOSEN` in `debug crypto isakmp`, remove the restrictions and run `tofu apply` again (takes ~9 minutes for AWS to propagate).

Phase 1 algorithm restrictions are unaffected by this issue.

### IOS XE version-specific command support

`crypto ikev2 fragmentation mtu 1200` was introduced in IOS XE 16.x. On older images, remove this line from the generated config — it is advisory (prevents fragmentation issues on strict-MTU paths) and not required for basic connectivity.

### First-negotiation traffic interruption

When IKEv1 SAs expire or are cleared, there will be a brief interruption (typically 2–5 seconds) while IKEv2 SA establishment completes. Plan accordingly for latency-sensitive applications.

---

## 15. Troubleshooting

### Tunnels don't come up after applying config

```
debug crypto ikev2 error
debug crypto ikev2 packet
```

Common causes:
- **PSK mismatch**: `IKEv2: (SA ID = 1) Proposed PSK does not match` — verify PSK values against AWS download
- **Algorithm mismatch**: AWS VGW rejected the proposal — check `show crypto ikev2 sa detail` for negotiated vs proposed
- **Firewall blocking**: UDP 500 and 4500 must be permitted inbound on the WAN interface (and any upstream firewall/NAT device)
- **Missing identity**: If AWS rejects the authentication, try adding `identity local address <wan-ip>` to the IKEv2 profile

### IKEv2 SA shows READY but no traffic flows

```
show crypto ipsec sa | include encaps|decaps|peer
```

- If `encaps > 0` but `decaps = 0`: traffic is going into the tunnel but return traffic isn't arriving — check VPC route table, security groups, and NACLs
- If `encaps = 0`: the crypto ACL isn't matching traffic — verify `match address` ACL and source/destination subnets

### AWS Console shows tunnel DOWN after migration

AWS tunnel status updates within ~60 seconds of an IKE SA changing state. If the status is DOWN:
1. Check `show crypto ikev2 sa` on the router — is the SA READY?
2. If the router shows READY but AWS shows DOWN, AWS may not have received the IKE_AUTH successfully — check `debug crypto ikev2` for errors
3. Ensure DPD is configured (`dpd 10 3 periodic` in the profile) — AWS sends DPD to detect liveness and will mark the tunnel DOWN if there is no response

### `show crypto ikev2 sa` shows nothing / tunnel not coming up

Check if there are stale IKEv1 SAs that need to expire first:

```
show crypto isakmp sa
```

If IKEv1 SAs are still ACTIVE (QM_IDLE), the tunnel is still operating on IKEv1. Either wait for the SA lifetime to expire or clear with `clear crypto isakmp` / `clear crypto sa` in a maintenance window.

### VTI tunnel line protocol is down (IKEv1)

Symptom: `show interfaces Tunnel1` shows `line protocol is down`; `show crypto isakmp sa` shows QM_IDLE (Phase 1 up) but `show crypto ipsec sa` shows zero SAs and outbound SPI = 0x0.

This is a Phase 2 negotiation failure. Run:

```
debug crypto isakmp
terminal monitor
clear crypto session
```

Watch for the error in the output. Common causes:

- **`PROPOSAL_NOT_CHOSEN`** — AWS rejected the Phase 2 proposal. If you have `Phase2EncryptionAlgorithms`, `Phase2IntegrityAlgorithms`, or `Phase2DHGroupNumbers` set on the AWS VPN connection, those must exactly match your router's transform-set. The simplest fix is to remove all Phase 2 algorithm restrictions from the AWS VPN connection (see Known Limitations).
- **`PAYLOAD_MALFORMED`** — often follows `PROPOSAL_NOT_CHOSEN` on retransmission; not an independent problem.
- **`INVALID_SPI`** — stale SA; clear with `clear crypto session` and retry.

### VTI tunnel is up but BGP neighbors won't establish

1. Confirm tunnel line protocol is up: `show interfaces Tunnel1`
2. Check BGP timers and state: `show ip bgp summary`
3. Confirm the BGP neighbor IPs match the VGW **inside** IPs (169.254.x.x/30 addresses from the AWS VPN config), not the outside IPs
4. Confirm no ACL is blocking TCP 179 on the tunnel interface

### BGP is up but ping to EC2 fails (no return traffic)

Most likely cause: the router is not advertising its LAN prefix to AWS, so EC2 has no route back.

```
show ip bgp summary               ← check "PfxRcd" column — should be 1 per neighbor
show ip bgp neighbors X.X.X.X advertised-routes
show ip route 10.0.1.0            ← must exist for BGP to advertise it
```

If `show ip route 10.0.1.0` returns nothing but you have a Loopback0 with a /32, add:

```
ip route 10.0.1.0 255.255.255.0 Null0
```

This creates the exact /24 prefix the BGP `network` command requires.

Also check EC2 side: the VPC route table must have the on-premises CIDR pointing at the VGW (either static route or route propagation enabled).

### IKEv2 SA shows nothing after applying VTI migration config (IOS XE)

If `show crypto ikev2 sa` is empty after applying the migration config on IOS XE:

1. Confirm the ipsec profile contains `set ikev2-profile AWS-IKEV2-PROFILE`: `show crypto ipsec profile`
2. Confirm the IKEv2 profile is correct: `show crypto ikev2 profile`
3. Clear sessions to force renegotiation: `clear crypto session`
4. Watch: `debug crypto ikev2 error` + `debug crypto ikev2 packet`

If tunnels go down and no IKEv2 activity is seen at all — no `IKEv2:(INIT)` lines in the debug — you may be on classic IOS (not IOS XE). Run `show version` and confirm the platform is IOS XE. Classic IOS 15.x on C2900 hardware cannot initiate IKEv2 for VTI tunnels.

### Running the test suite

```bash
python3 test_ikev1_to_ikev2_migrate.py
```

All 104 tests should pass. This validates the parser, weak-algorithm detection, config generation, VTI/BGP support, YANG payload structure, and end-to-end output correctness without requiring any network access.

---

## 16. Lab Environment (OpenTofu/Terraform)

The `terraform/` directory contains a complete OpenTofu configuration that recreates the AWS lab used to validate this tool. It builds a VPC with an EC2 ping target, a VGW with a two-tunnel Site-to-Site VPN Connection, and generates ready-to-paste IKEv2 router config from the outputs.

### Prerequisites

```bash
# macOS
brew install opentofu

# AWS credentials — must be in ~/.aws/credentials or environment variables
# The account needs EC2 full access (VPC, VPN, EC2 instance)
```

### First-time setup

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
router_public_ip = "68.48.149.112"   # your router's current public IP
                                      # resolve mindfury.duckdns.org first if dynamic
onprem_cidr      = "10.0.1.0/24"     # your LAN subnet — must match BGP network statement
tunnel1_psk      = "LabPSKTunnel1A"  # 8–64 chars, alphanumeric + _ + . only
tunnel2_psk      = "LabPSKTunnel2B"  # must differ from tunnel1_psk
```

> `terraform.tfvars` contains PSKs — it is gitignored by the example. Never commit it.

### Deploy

```bash
tofu init      # downloads AWS provider (~30s, first time only)
tofu plan      # preview what will be created
tofu apply     # deploy (~5–9 minutes, mostly waiting for VPN Connection)
```

The lab uses `static_routes_only = false` (BGP/dynamic routing mode) to match real-world VTI/BGP deployments.

> **Note:** Do not add Phase 2 algorithm restrictions (`tunnel1_phase2_*` variables) to the VPN connection unless you have verified exact algorithm alignment with the router's transform-set. These restrictions cause immediate `PROPOSAL_NOT_CHOSEN` rejections for IKEv1 Phase 2 negotiations that don't match exactly.

### Push the pre-migration IKEv1 VTI/BGP config to the lab router

After `tofu apply`, push the IKEv1 config to the ISR 2911 (or other lab router):

```bash
# Dry run — shows what would be pushed without connecting
python3 scripts/push_lab_config.py --dry-run

# Push config and run verification checks
python3 scripts/push_lab_config.py --verify
```

Expected result after push:
- Both tunnels UP (IKEv1, NAT-T on port 4500)
- BGP established with both AWS VGW neighbors, 1 prefix received per tunnel
- Ping to EC2 target 5/5

### Get the router config outputs

```bash
tofu output tunnel1_outside_ip   # AWS VGW tunnel 1 endpoint
tofu output tunnel2_outside_ip   # AWS VGW tunnel 2 endpoint
tofu output ec2_private_ip       # ping target inside the VPC
tofu output -json | python3 -c "import json,sys; d=json.load(sys.stdin); [print(k,'=',v['value']) for k,v in d.items() if not v.get('sensitive')]"
```

### Test the migration tool against it

```bash
# 1. Capture the running config
ssh -o KexAlgorithms=diffie-hellman-group14-sha1 admin@c2911.internal "show running-config" > running.cfg

# 2. Audit — should show WEAK-PFS and VTI/BGP detected
python3 ikev1_to_ikev2_migrate.py --config-file running.cfg --audit-only

# 3. Generate IKEv2 additions
python3 ikev1_to_ikev2_migrate.py --config-file running.cfg > ikev2_additions.txt

# 4. Apply to router (IOS XE only — IOS 15.7 on 2911 cannot initiate IKEv2 for VTI)
# show crypto ikev2 sa   → expect READY, AES-CBC/SHA512/DH-21
# show ip bgp summary    → expect Established (BGP unchanged)
# ping <ec2_private_ip> source Loopback0 repeat 10
```

### Tear down (stop billing)

The VPN Connection costs ~$0.05/hr. When you are done:

```bash
tofu destroy
```

Terraform tracks all resource IDs in `terraform.tfstate` — destroy is clean and complete. To rebuild later, just run `tofu apply` again (update `router_public_ip` in `terraform.tfvars` first if your IP has changed).

### What Terraform creates

| Resource | Purpose | Cost |
|---|---|---|
| VPC `10.10.0.0/16` | Isolated network for lab | Free |
| Subnet `10.10.1.0/24` | EC2 placement | Free |
| Internet Gateway | Outbound connectivity | Free |
| Route table | IGW default route + on-prem via VGW | Free |
| Security group | Allow ICMP from on-prem LAN | Free |
| EC2 t3.nano | Ping target in VPC | ~$0.005/hr |
| Customer Gateway | Represents your router in AWS | Free |
| Virtual Private Gateway | AWS VPN endpoint, attached to VPC | Free |
| VPN Connection (2 tunnels) | The actual IPsec VPN | ~$0.05/hr |

**Total while running: ~$0.055/hr (~$1.32/day)**

Tunnel options are configured to match this tool's constants exactly:
IKEv2-only, AES-256, SHA-512, DH group 21 for both Phase 1 and Phase 2.
