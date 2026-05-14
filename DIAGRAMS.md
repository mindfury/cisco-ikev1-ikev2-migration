# Dependency Graphs

---

## AWS Lab Object Dependencies

Every resource the lab Terraform creates, what it does, and what it depends on.
Arrows mean "depends on / references."

```mermaid
flowchart TD
    %% Inputs
    VAR_IP["var.router_public_ip\nISR 2911 public IP"]
    VAR_BGP["var.router_bgp_asn = 65000"]
    AMI["data.aws_ami.al2023\nlatest AL2023 HVM x86_64"]

    %% VPC layer
    VPC["aws_vpc.lab\n10.10.0.0/16\nIsolated network boundary"]
    SUBNET["aws_subnet.lab\n10.10.1.0/24 in us-east-1a\nEC2 placement subnet"]
    IGW["aws_internet_gateway.lab\nOutbound internet for EC2"]
    RT["aws_route_table.lab\n0.0.0.0/0 → IGW\nDefault route + BGP propagation"]
    RTA["aws_route_table_association.lab\nBinds subnet to route table"]
    SG["aws_security_group.lab\nAllow ICMP from on-prem + VPC\nDeny everything else inbound"]

    %% EC2
    EC2["aws_instance.target  t3.nano\n10.10.1.200\nPing target inside VPC"]

    %% VPN objects
    CGW["aws_customer_gateway.lab\nRepresents the ISR 2911 to AWS\nHolds router public IP + BGP ASN"]
    VGW["aws_vpn_gateway.lab\nAWS-side VPN endpoint\nAttached to VPC"]
    PROP["aws_vpn_gateway_route_propagation.lab\nInserts BGP-learned on-prem routes\ninto route table automatically"]
    VPN["aws_vpn_connection.lab\nvpn-0c38e6d3a4d5321c3\nTwo IPsec tunnels, IKEv1+IKEv2\nBGP mode, asymmetric PSKs"]

    %% Dependencies
    VPC --> SUBNET
    VPC --> IGW
    VPC --> RT
    IGW --> RT
    RT --> RTA
    SUBNET --> RTA
    VPC --> SG

    AMI --> EC2
    SUBNET --> EC2
    SG --> EC2

    VAR_IP --> CGW
    VAR_BGP --> CGW
    VPC --> VGW
    VGW --> VPN
    CGW --> VPN
    VGW --> PROP
    RT --> PROP
```

### BGP route propagation flow (runtime, not a Terraform dependency)

```
ISR 2911                       AWS VGW                    VPC Route Table
────────                       ───────                    ───────────────
router bgp 65000         BGP session over          aws_vpn_gateway_
  network 10.0.1.0/24 ──▶ tunnel inside IPs  ──▶  route_propagation
                           (169.254.x.x)            inserts 10.0.1.0/24
                                                     → vgw-01d4b1add27b92d27
```

---

## Cisco IKEv1 VTI + BGP Config Dependencies

Objects present on the router **before** migration. Arrows mean "references / depends on."

```mermaid
flowchart TD
    %% Physical
    GE0["interface GigabitEthernet0/0\nWAN interface — DHCP public IP\nSource for all tunnel traffic"]

    %% IKEv1 Phase 1
    P1["crypto isakmp policy 10\nPhase 1 (IKE) parameters\nenc AES-256 / hash SHA-256\ngroup14 / lifetime 28800s"]
    KEY1["crypto isakmp key PSK1\naddress 35.169.156.239\nPSK for Tunnel 1 peer"]
    KEY2["crypto isakmp key PSK2\naddress 50.19.54.34\nPSK for Tunnel 2 peer"]

    %% Phase 2
    TS["crypto ipsec transform-set TS-AWS-VTI\nPhase 2 cipher suite\nesp-aes256 / esp-sha256-hmac\nmode tunnel"]
    PROF["crypto ipsec profile AWS-VTI-PROFILE\nBinds transform-set to VTI tunnels\nset pfs group2  ← FN72510 target"]

    %% Tunnel interfaces
    T1["interface Tunnel1\nInside IP: 169.254.107.58/30\ndest: 35.169.156.239 (outside)\ntunnel protection → ipsec profile"]
    T2["interface Tunnel2\nInside IP: 169.254.16.114/30\ndest: 50.19.54.34 (outside)\ntunnel protection → ipsec profile"]

    %% Routing
    LO["interface Loopback0\n10.0.1.1/32\nRouter ID + BGP source prefix"]
    NULLRT["ip route 10.0.1.0/24 Null0\nCreates exact /24 in RIB so BGP\ncan advertise it (Loopback is /32)"]
    BGP["router bgp 65000\nneighbors: 169.254.107.57 + 169.254.16.113\n(VGW inside IPs, remote-as 64512)\nnetwork 10.0.1.0/24"]

    %% Dependency edges
    TS --> PROF
    PROF --> T1
    PROF --> T2
    GE0 --> T1
    GE0 --> T2
    KEY1 -.->|"peer IP matches\ntunnel destination"| T1
    KEY2 -.->|"peer IP matches\ntunnel destination"| T2
    P1 -.->|"governs IKE negotiation\nfor all peers"| T1
    P1 -.->|"governs IKE negotiation\nfor all peers"| T2
    T1 -->|"makes 169.254.107.57\nreachable"| BGP
    T2 -->|"makes 169.254.16.113\nreachable"| BGP
    LO -->|"source prefix"| BGP
    NULLRT -->|"exact /24 match\nenables network stmt"| BGP
```

**Solid arrows** = hard config reference (object A names object B).  
**Dashed arrows** = runtime dependency (A won't work without B, but A doesn't name B in config).

---

## Cisco IKEv2 Migration Additions

Objects the migration tool **adds** to the existing config. The ipsec profile is updated in-place; everything else is new. Existing IKEv1 objects are not shown but remain untouched.

```mermaid
flowchart TD
    %% New IKEv2 objects
    PROP2["crypto ikev2 proposal AWS-IKEV2-PROPOSAL\nPhase 1 parameters (IKEv2)\nenc AES-CBC-256 / integ SHA-512\nprf SHA-512 / DH group21"]
    POL2["crypto ikev2 policy AWS-IKEV2-POLICY\nActivates proposal for any fvrf"]
    KR["crypto ikev2 keyring AWS-IKEV2-KEYRING\nPSK database — one peer block\nper tunnel outside IP\nlocal + remote PSK (same value)"]
    IKV2PROF["crypto ikev2 profile AWS-IKEV2-PROFILE\nPer-peer coordinator\nmatch identity remote 0.0.0.0\nkeyring → AWS-IKEV2-KEYRING\ndpd 10 3 periodic / lifetime 28800s"]
    TSV2["crypto ipsec transform-set TS-AWS-VTI-V2\nUpgraded Phase 2 cipher suite\nesp-aes256 / esp-sha512-hmac\n(created only if original TS is weak)"]

    %% Updated existing object
    PROFUPD["crypto ipsec profile AWS-VTI-PROFILE  ← updated\nset transform-set TS-AWS-VTI-V2\nset pfs group21\nset ikev2-profile AWS-IKEV2-PROFILE  ← activation switch"]

    %% Tunnel interfaces — unchanged but now governed by IKEv2
    T1U["interface Tunnel1\n(unchanged — still references same ipsec profile)"]
    T2U["interface Tunnel2\n(unchanged — still references same ipsec profile)"]

    %% Edges
    PROP2 --> POL2
    KR --> IKV2PROF
    IKV2PROF --> PROFUPD
    TSV2 --> PROFUPD
    PROFUPD --> T1U
    PROFUPD --> T2U
```

### What the activation switch does

```
crypto ipsec profile AWS-VTI-PROFILE
  set ikev2-profile AWS-IKEV2-PROFILE   ← present  → IKEv2 initiates on next renegotiation
                                         ← absent   → IKEv1 (full rollback)
```

The tunnel interfaces and BGP config require **zero changes**. BGP neighbors operate over the same 169.254.x.x/30 inside IPs regardless of whether the tunnel is protected by IKEv1 or IKEv2.

---

## Full Stack: How a Packet Gets Encrypted (VTI Path)

```
Application packet: 10.0.1.1 → 10.10.1.200
        │
        ▼
┌─ Routing table ─────────────────────────────────────────────┐
│  10.10.0.0/16 via Tunnel1 (BGP-learned from VGW)           │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─ interface Tunnel1 ─────────────────────────────────────────┐
│  tunnel protection ipsec profile AWS-VTI-PROFILE           │
│    → looks up IPsec SA for tunnel destination 35.169.x.x   │
│    → if no SA: triggers IKE (v1 or v2 per profile config)  │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─ IKE negotiation (one-time, on SA miss) ────────────────────┐
│  Phase 1: isakmp policy / ikev2 proposal                   │
│    → agree on enc/hash/DH, derive shared key               │
│  Phase 2: ipsec profile → transform-set                    │
│    → agree on ESP cipher, derive session keys              │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌─ ESP encapsulation ─────────────────────────────────────────┐
│  Inner packet: 10.0.1.1 → 10.10.1.200                     │
│  Outer packet: GigEth0/0-IP → 35.169.156.239 (UDP 4500)   │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
    Public internet → AWS VGW decapsulates → 10.10.1.200 (EC2)
```
