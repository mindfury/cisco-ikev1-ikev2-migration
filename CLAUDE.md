# CLAUDE.md — Agent Handoff Notes

## Project

Cisco IOS XE IKEv1 → IKEv2 migration helper for AWS Site-to-Site VPNs.

Primary script: `ikev1_to_ikev2_migrate.py`  
Tests: `test_ikev1_to_ikev2_migrate.py`  
Migration procedure: `MIGRATION.md`

```bash
python3 test_ikev1_to_ikev2_migrate.py   # 104 tests, no pytest required
```

---

## Target platform

| Item | Value |
|---|---|
| Production device | Cisco ISR 4431, IOS XE 17.09.05a |
| Migration driver | FN72510 — weak crypto blocked in IOS XE 17.11+; migrate before upgrading |
| AWS side | Two tunnels per VPN connection; PSKs are read-only after creation |
| Strategy | Additive migration — IKEv1 left in place for rollback |

---

## VPN topology support

### Policy-based (crypto map)

```ios
crypto map CMAP-AWS 10 ipsec-isakmp
 set peer 1.2.3.4
 set transform-set TS-AWS
 match address ACL-AWS
```

Migration activation: add `set ikev2-profile AWS-IKEV2-PROFILE` to each crypto map entry.

### Route-based (VTI + BGP)

```ios
interface Tunnel1
 tunnel protection ipsec profile AWS-VTI-PROFILE

crypto ipsec profile AWS-VTI-PROFILE
 set transform-set TS-AWS-VTI
 set pfs group14
```

Migration activation: add `set ikev2-profile AWS-IKEV2-PROFILE` to the `crypto ipsec profile`.  
BGP is **not touched** — tunnel inside IPs, neighbor IPs, ASNs, and routing policy are unchanged.

---

## IKEv1 and IKEv2 coexistence — important clarification

IKEv1 and IKEv2 **can and do coexist on UDP 500/4500 simultaneously**. They do not conflict.
Every IKE packet carries a Major Version field in its header (byte 17). The router's IKE daemon
reads this on arrival and dispatches to the correct protocol handler. IOS XE maintains entirely
separate SA databases (`show crypto isakmp sa` vs `show crypto ikev2 sa`).

This is the foundation of the additive migration strategy: IKEv2 SAs come up alongside existing
IKEv1 SAs, traffic validation proceeds, and IKEv1 config is removed only once IKEv2 is confirmed
stable. AWS VGW supports both versions concurrently on the same tunnel endpoint.

---

## Confirmed algorithms (ISR 4431 / IOS XE 17.09.05a)

| Layer | Algorithm |
|---|---|
| IKEv2 Phase 1 encryption | AES-CBC-256 (AES-GCM unavailable on this image) |
| IKEv2 Phase 1 integrity | SHA-512 |
| IKEv2 Phase 1 PRF | SHA-512 |
| IKEv2 Phase 1 DH group | 21 (521-bit ECP) |
| IPsec Phase 2 ESP | esp-aes 256 esp-sha256-hmac |
| IPsec Phase 2 PFS | group 14 (carried over from IKEv1; upgrade to 21 if schedule allows) |

Do not change these to aes-gcm-256 or group 20 — they are not available on 17.09.05a.

---

## Platform caveats

### IOS 15.x (classic IOS) does NOT initiate IKEv2 for VTI

Tested on ISR 2911 / IOS 15.7(3)M3. Even with `set ikev2-profile` correctly placed in the
`crypto ipsec profile` and the IKEv1 ISAKMP policy removed, zero IKEv2 SA activity is observed.
The commands are syntactically accepted but the VTI SA engine does not trigger IKEv2 initiation.

**IKEv2 VTI migration requires IOS XE** (ISR 4000 series, CSR1000v, Cat8000v). Classic IOS
15.x can validate IKEv1 baselines and migration config generation only.

For policy-based (crypto map) VPNs, IOS 15.x IKEv2 behavior has not been tested — it may work
since that code path is different from VTI. Do not assume it works without testing.

### IOS XE version requirement for FN72510

The target platform is ISR 4431 on IOS XE 17.09.05a. Upgrade path is → 17.12.x. The tool
generates config that is compliant with 17.11+ crypto policy enforcement.

---

## AWS-side caveats

### Phase 2 algorithm restrictions in Terraform break IKEv1 QM

Setting `tunnel1_phase2_dh_group_numbers`, `tunnel1_phase2_encryption_algorithms`, or
`tunnel1_phase2_integrity_algorithms` on an `aws_vpn_connection` resource causes AWS to
immediately reject IKEv1 Phase 2 (Quick Mode) proposals with `PROPOSAL_NOT_CHOSEN` — even when
the router's proposal appears to match. Root cause is not fully understood. These attributes are
currently absent from `terraform/main.tf`; do not add them back without careful per-value testing.

### PSKs are symmetric per tunnel

Standard AWS Site-to-Site VPN uses the same PSK for both local and remote authentication on each
tunnel. The keyring should set:
```ios
pre-shared-key local <PSK>
pre-shared-key remote <PSK>
```
with the same value on both sides.

### AWS VPN allows both IKE versions on the same tunnel endpoint

`tunnel1_ike_versions = ["ikev1", "ikev2"]` is how the lab Terraform is configured. AWS VGW
handles both concurrently. There is no need to create separate VPN connections for IKEv1 and
IKEv2 during a migration window.

---

## Router-side caveats

### IKEv2 and NAT-T (router behind NAT)

When the router is behind NAT, IKEv1 detects NAT and switches to UDP 4500 (NAT-T). IKEv2 also
uses UDP 4500 automatically when NAT is detected. Both work through the same NAT mapping.

Add keepalives to maintain the NAT pinhole:
```ios
crypto isakmp keepalive 10 3          ! IKEv1
crypto ikev2 profile ... / dpd 10 3 periodic   ! IKEv2
```

### Transform set mode for VTI

Cisco IOS documentation is inconsistent on this. Both `mode tunnel` and `mode transport` in the
transform set are accepted for VTI profiles. `mode tunnel` is what AWS-generated config examples
show and is what was validated in the lab. Do not change it.

### KB-based SA lifetime causes issues with AWS

The IOS default IPsec SA lifetime includes a kilobyte component (4,608,000 KB). Disable it in
the ipsec profile to avoid potential negotiation issues with AWS:
```ios
crypto ipsec profile AWS-VTI-PROFILE
 set security-association lifetime kilobytes disable
 set security-association lifetime seconds 3600
```

### BGP null-route requirement

If the on-prem loopback is `/32` but BGP is configured with `network x.x.x.0 mask 255.255.255.0`,
IOS BGP will not advertise the /24 because there is no exact match in the RIB. Add:
```ios
ip route 10.0.1.0 255.255.255.0 Null0
```
Without this, the remote side has no return path and pings will be one-way.

---

## Code structure

```
ikev1_to_ikev2_migrate.py
├── ConfigParser          — parses IKEv1 IOS config text into dataclasses
│   ├── IsakmpPolicy, IsakmpKey, TransformSet, CryptoMapEntry
│   ├── IpsecProfile, TunnelInterface, BgpNeighbor   (VTI/BGP)
│   └── parse()           — entry point, returns ParsedConfig
├── IKEv2ConfigGenerator  — generates IKEv2 CLI additions from ParsedConfig
│   ├── _gen_ikev2_proposal/policy/keyring/profile()
│   ├── _gen_cryptomap_updates()     — policy-based path
│   ├── _gen_vti_profile_updates()   — route-based path
│   └── generate()        — returns list of config lines
└── main()                — CLI: --config-file / --device / --audit-only
```

RESTCONF device mode (`--device`) is implemented but only tested with crypto-map configs.
VTI/BGP device mode support has not been validated end-to-end.

---

## Lab infrastructure

```
terraform/
├── main.tf           — VPC, VGW, CGW, VPN connection (BGP mode, IKEv1+IKEv2)
├── outputs.tf        — tunnel IPs, BGP ASN, EC2 IP, pre-migration router_config
├── variables.tf      — aws_region, router_public_ip, router_bgp_asn, PSKs
└── terraform.tfvars  — gitignored; contains real PSKs and public IP

scripts/
└── push_lab_config.py   — SSH PTY-based config push to c2911.internal
                           reads tofu outputs, pushes IKEv1 VTI/BGP pre-migration config
```

Lab router: `c2911.internal` — ISR 2911, IOS 15.7(3)M3, creds in push script.

SSH requires legacy KEX (IOS 15.x):
```python
asyncssh.connect(host, known_hosts=None,
    kex_algs=["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"],
    server_host_key_algs=["ssh-rsa"])
```

IOS 15.x requires a PTY for multi-line config blocks — `conn.run()` closes after one command.
Use `create_process(request_pty=True, term_type="vt100")` and send lines one at a time.

---

## What is and is not done

| Item | Status |
|---|---|
| Policy-based (crypto map) parsing + generation | Done, tested |
| VTI/BGP parsing + generation | Done, tested |
| IKEv1 VTI/BGP baseline — AWS lab end-to-end | Validated ✓ |
| IKEv2 SA establishment — policy-based (ISR 4431) | Validated ✓ |
| IKEv2 SA establishment — VTI/BGP (ISR 4431) | Not yet validated (need IOS XE hardware) |
| RESTCONF device mode — VTI/BGP | Not validated |
| Production ISR 4431 migration | Not yet executed |

---

## Do not commit

- `terraform/terraform.tfvars` — PSKs and public IP (gitignored)
- `running.cfg` — captured router config with live PSKs (gitignored)
- Any file matching `*.tfstate`, `*.tfstate.backup`
