# cisco-ikev1-ikev2-migration

Migrates Cisco IOS / IOS XE IPsec VPN tunnels from IKEv1 to IKEv2, driven by Cisco Field Notice **FN72510** — weak crypto algorithms (DES/3DES, MD5, DH groups 1/2/5/24) are blocked in IOS XE 17.11+. Any tunnel using those algorithms will drop on the first IKE renegotiation after upgrading.

Validated end-to-end against a live AWS Virtual Private Gateway: IKEv2 SA READY (AES-CBC-256 / SHA-512 / DH group 21), traffic flowing, rollback confirmed.

---

## How it works

The migration is **additive** — IKEv1 config is left completely untouched. New IKEv2 objects are placed alongside. The activation switch is one line per crypto map entry:

```
set ikev2-profile <name>
```

Add it → IKEv2. Remove it → IKEv1. No other changes needed to roll back.

---

## Usage

### Prerequisites

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### File mode — works on any IOS or IOS XE device

```bash
# Capture running config
ssh admin@<router> "show running-config" > running.cfg

# Audit what needs migrating
python3 ikev1_to_ikev2_migrate.py --config-file running.cfg --audit-only

# Generate IKEv2 additions (review before applying)
python3 ikev1_to_ikev2_migrate.py --config-file running.cfg > ikev2_additions.txt
```

### Device mode — IOS XE with RESTCONF (ISR4431 / CSR1000v)

```bash
python3 ikev1_to_ikev2_migrate.py \
  --device 192.0.2.1 \
  --username admin \
  --password <password> \
  --dry-run    # remove to apply
```

---

## What gets generated

| IKEv1 object | IKEv2 replacement |
|---|---|
| `crypto isakmp policy` | `crypto ikev2 proposal` + `crypto ikev2 policy` |
| `crypto isakmp key` | `crypto ikev2 keyring` (peer blocks) |
| *(no equivalent)* | `crypto ikev2 profile` (per-peer coordinator) |
| `crypto ipsec transform-set` | Reused or upgraded to `esp-aes 256 esp-sha512-hmac` |
| `crypto map … set peer` | `crypto map … set ikev2-profile` added |

Algorithms used: **AES-CBC-256 / SHA-512 / PRF SHA-512 / DH group 21 / PFS group21** — confirmed available on ISR4431 IOS XE 17.09.05a, within the AWS VGW supported set, and clear of all FN72510 blocked values.

---

## Tests

```bash
python3 -m pytest test_ikev1_to_ikev2_migrate.py -v
```

101 tests covering parser edge cases (IOS abbreviations, implicit defaults), weak-algorithm detection, IKEv2 config generation, YANG payload structure, and end-to-end output correctness. No network access required.

---

## Lab environment

`terraform/` contains an OpenTofu configuration that rebuilds the AWS test lab:
VPC, VGW, two-tunnel Site-to-Site VPN Connection, and an EC2 ping target.
The `router_config` output generates ready-to-paste Cisco IKEv2 CLI with actual tunnel IPs and PSKs.

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars   # fill in router IP + PSKs
tofu init && tofu apply
tofu output -json router_config | python3 -c "import json,sys; print(json.load(sys.stdin))"
tofu destroy   # when done — ~$0.05/hr while running
```

---

## Documentation

| File | Contents |
|---|---|
| `HOWTO.md` | Step-by-step migration guide, AWS side preparation, rollback, troubleshooting |
| `IPsec-VPN-Primer.md` | Visual primer with Mermaid diagrams — IKEv1/IKEv2 object relationships, two-phase model, AWS architecture, Cisco↔AWS Rosetta Stone |

---

## Target platform

- **Production:** Cisco ISR4431, IOS XE 17.09.05a
- **Lab validated:** Cisco ISR 2911, IOS 15.7(3)M3, behind OPNsense NAT-T
- **AWS:** Site-to-Site VPN with Virtual Private Gateway (static routing, two tunnels)

## Known limitations

- Type 6 encrypted PSKs are not decryptable — tool emits a placeholder you must replace
- RESTCONF device mode is structurally complete but not yet validated against a live ISR4431
- Classic IOS (15.x) supported in file mode only — no RESTCONF

See `HOWTO.md` section 13 for the full list.
