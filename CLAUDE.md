# CLAUDE.md — Agent Handoff Notes

## Project

Cisco IOS / IOS XE IKEv1 → IKEv2 migration helper for AWS Site-to-Site VPNs.

Primary script:

- `ikev1_to_ikev2_migrate.py`

Tests:

- `test_ikev1_to_ikev2_migrate.py`

Run tests with:

```bash
python3 test_ikev1_to_ikev2_migrate.py
```

`pytest` is optional; the test file runs directly with stdlib `unittest`.

## Current status

The original tool was validated for **crypto-map / policy-based** AWS VPNs. During review, Phil raised an important production concern: several work VPNs use **VTIs with BGP over IPsec**.

That concern was valid. The original parser/generator targeted only:

```ios
crypto map <name> <seq> ipsec-isakmp
```

and activated IKEv2 by adding:

```ios
set ikev2-profile <profile>
```

under crypto-map entries.

Route-based AWS VPNs with BGP usually look more like:

```ios
interface Tunnel1
 ip address 169.254.x.y 255.255.255.252
 tunnel source <wan-interface>
 tunnel mode ipsec ipv4
 tunnel destination <aws-outside-ip>
 tunnel protection ipsec profile <IPSEC-PROFILE>

crypto ipsec profile <IPSEC-PROFILE>
 set transform-set <TRANSFORM-SET>
 set pfs group2

router bgp <local-as>
 neighbor 169.254.x.x remote-as 7224
```

For that shape, the IKEv2 activation belongs under the **crypto ipsec profile**, not under a crypto map:

```ios
crypto ipsec profile <IPSEC-PROFILE>
 set transform-set <TRANSFORM-SET-V2>
 set pfs group21
 set ikev2-profile AWS-IKEV2-PROFILE
```

BGP should remain unchanged as long as tunnel inside IPs, neighbor IPs, ASNs, and routing policy are unchanged.

## Work completed in this handoff

Added file-mode VTI/BGP support:

- New dataclasses:
  - `IpsecProfile`
  - `TunnelInterface`
  - `BgpNeighbor`
- `ConfigParser` now parses:
  - `crypto ipsec profile <name>`
  - `set transform-set ...`
  - `set pfs ...`
  - `set ikev2-profile ...`
  - `interface Tunnel*`
  - `ip address ...`
  - `tunnel source ...`
  - `tunnel mode ...`
  - `tunnel destination ...`
  - `tunnel protection ipsec profile ...`
  - `router bgp` neighbor `remote-as` lines
- `IKEv2ConfigGenerator` now:
  - detects unmigrated VTI tunnel profiles
  - includes VTI tunnel destinations in keyring peer matching
  - includes transform-sets referenced by IPsec profiles in weak-transform replacement logic
  - emits `crypto ipsec profile ... set ikev2-profile AWS-IKEV2-PROFILE`
  - emits a BGP review note but does not modify BGP
- Added VTI/BGP tests in `test_ikev1_to_ikev2_migrate.py`.
- Current test result at handoff:

```text
Ran 104 tests
OK
```

## Important caveats

1. **RESTCONF/device mode is still crypto-map-oriented.**
   - The new VTI support is for file-mode generated CLI.
   - Do not assume RESTCONF PATCH mode can safely update VTI/IPsec profile configs yet.

2. **Terraform lab is still static-routing / crypto-map oriented.**
   - Current `terraform/main.tf` uses:

   ```hcl
   static_routes_only = true
   ```

   - That lab does not validate BGP-over-VTI behavior.
   - Before using AWS to validate the production concern, add a dynamic-routing/BGP lab variant with `static_routes_only = false` and generated Cisco VTI/BGP config.

3. **Do not paste or commit real PSKs.**
   - Generated output may include PSKs from captured configs.
   - Use sanitized configs for tests and commits.

4. **AWS PSKs are normally symmetric per tunnel.**
   - The code comment was corrected to say standard AWS S2S uses the same PSK for local and remote on each tunnel.

## Recommended next steps

1. Capture/sanitize the powered-up 2911 config:

```bash
ssh <user>@<2911-ip> "show running-config" > 2911-running.cfg
```

Sanitize secrets before committing or sharing:

- `crypto isakmp key ...`
- any usernames/passwords/secrets
- public IPs if desired

2. Run audit and generated config:

```bash
python3 ikev1_to_ikev2_migrate.py --config-file 2911-running.cfg --audit-only
python3 ikev1_to_ikev2_migrate.py --config-file 2911-running.cfg > ikev2-generated.cfg
```

3. Review generated VTI output carefully:

- keyring peer IPs match AWS outside tunnel IPs
- PSKs match AWS config download
- transform-set replacement is appropriate
- `crypto ipsec profile` references the new transform-set and `set ikev2-profile`
- Tunnel interface config is not modified
- BGP neighbor config is not modified

4. Add a dynamic-routing AWS lab before live validation:

- `static_routes_only = false`
- AWS CGW BGP ASN = lab router ASN
- Generate Cisco VTI tunnel interfaces
- Generate `router bgp` neighbors using AWS inside tunnel IPs
- Validate BGP adjacency and route exchange before/after IKEv2 migration

## Mental model

For policy-based VPN:

```ios
crypto map entry + ACL decides what enters IPsec
```

For route-based VTI VPN:

```ios
routing sends packets into TunnelX
TunnelX uses tunnel protection ipsec profile
crypto ipsec profile binds transform-set + IKEv2 profile
BGP runs over the tunnel inside IPs
```

So for VTI/BGP, converting IKEv1→IKEv2 should be a crypto/profile change, not a routing/BGP/tunnel-address change.
