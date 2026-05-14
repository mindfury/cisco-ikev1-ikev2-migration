#!/usr/bin/env python3
"""
ikev1_to_ikev2_migrate.py
--------------------------
Migrates Cisco IOS XE IKEv1 IPsec tunnels to IKEv2, FN72510-compliant.

Two modes of operation:

  FILE MODE (--config-file):
    Reads a startup/running-config text file, generates a ready-to-paste
    IKEv2 config block. IKEv1 config is left untouched.

  DEVICE MODE (--device):
    1. GETs current crypto config from device via RESTCONF
    2. Parses IKEv1 objects and identifies weak algorithms
    3. Generates IKEv2 additions (proposal/policy/keyring/profile/transform-sets)
    4. PATCHes the new objects back (unless --dry-run)
    5. Validates via RESTCONF GET + 'show crypto ikev2 sa' (netmiko)

Target platform: Cisco ISR4431, IOS XE 17.09.05a
Confirmed algorithms: AES-CBC-256, SHA-512, DH group 21, esp-aes 256 esp-sha512-hmac

Usage:
  # File mode
  python3 ikev1_to_ikev2_migrate.py --config-file running.cfg [--aws-peer IP] [--audit-only]

  # Device mode
  python3 ikev1_to_ikev2_migrate.py --device 192.0.2.1 --username admin --password secret \\
      [--aws-peer IP] [--dry-run] [--audit-only] [--port 443] [--no-verify-ssl]
"""

import re
import sys
import json
import argparse
import urllib3
import logging
from dataclasses import dataclass, field
from typing import Optional

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    requests = None  # only needed in device mode

try:
    from netmiko import ConnectHandler
except ImportError:
    ConnectHandler = None  # only needed for post-PATCH validation

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Algorithm constants — confirmed available on ISR4431 IOS XE 17.09.05a
# ---------------------------------------------------------------------------

# AES-GCM is NOT available on 17.09.05a; AES-CBC-256 with explicit integrity is
# required. DH group 21 (521-bit ECP) is the highest available on this image.

MODERN_IKE_ENCRYPTION = "aes-cbc-256"    # GCM unavailable on 17.09.05a
MODERN_IKE_INTEGRITY  = "sha512"          # required when encryption is CBC
MODERN_IKE_PRF        = "sha512"
MODERN_IKE_DH_GROUP   = "21"             # 521-bit ECP; group14/19/20/21 available
MODERN_ESP_ENC        = "esp-aes"
MODERN_ESP_KEY_BIT    = "256"
MODERN_ESP_HMAC       = "esp-sha512-hmac"
MODERN_PFS_GROUP      = "group21"
AWS_SA_LIFETIME       = 28800            # 8h — matches AWS IKEv2 default

# IKEv1 / transform-set weak algorithm sets (FN72510 blocklist)
WEAK_ISAKMP_ENCRYPTION = {"des", "3des"}
WEAK_ISAKMP_HASH       = {"md5"}
WEAK_ISAKMP_GROUPS     = {"1", "2", "5", "24"}

WEAK_TRANSFORM_ESP_ENC = {"esp-des", "esp-3des", "esp-null", "esp-gmac"}
WEAK_TRANSFORM_ESP_INT = {"esp-md5-hmac"}
WEAK_TRANSFORM_AH      = {"ah-md5-hmac"}
WEAK_PFS_GROUPS        = {"group1", "group2", "group5", "group24"}

# ---------------------------------------------------------------------------
# YANG mapping tables (IKEv2 proposal group container uses spelled-out names)
# ---------------------------------------------------------------------------

DH_GROUP_TO_YANG = {
    "1": "one",        "2": "two",        "5": "five",
    "14": "fourteen",  "15": "fifteen",   "16": "sixteen",
    "19": "nineteen",  "20": "twenty",    "21": "twenty-one",
    "24": "twenty-four",
}
YANG_TO_DH_GROUP = {v: k for k, v in DH_GROUP_TO_YANG.items()}

PFS_GROUP_TO_YANG = {f"group{n}": n for n in ("1","2","5","14","15","16","19","20","21","24")}

# Maps YANG isakmp encryption container leaves → canonical names used in the dataclasses
ISAKMP_ENC_YANG_LEAF = {
    "a3des":     "3des",
    "aes-256":   "aes 256",
    "aes-192":   "aes 192",
    "aes-choice": None,   # resolved by key-type sub-leaf
    "des-choice": "des",
}

# ---------------------------------------------------------------------------
# Data classes (shared between file-mode and RESTCONF-mode parsers)
# ---------------------------------------------------------------------------

@dataclass
class IsakmpPolicy:
    priority: str
    encryption: Optional[str] = None
    hash_alg: Optional[str] = None
    group: Optional[str] = None
    lifetime: Optional[str] = None
    auth: Optional[str] = None

    def has_weak_algo(self) -> bool:
        return (
            self.encryption in WEAK_ISAKMP_ENCRYPTION or
            self.hash_alg   in WEAK_ISAKMP_HASH or
            self.group      in WEAK_ISAKMP_GROUPS
        )


@dataclass
class IsakmpKey:
    key: str
    peer_ip: str
    peer_mask: Optional[str] = None


@dataclass
class TransformSet:
    name: str
    transforms: list = field(default_factory=list)
    mode: Optional[str] = None

    def has_weak_algo(self) -> bool:
        for t in self.transforms:
            tl = t.lower()
            if any(w in tl for w in WEAK_TRANSFORM_ESP_ENC | WEAK_TRANSFORM_ESP_INT | WEAK_TRANSFORM_AH):
                return True
        return False


@dataclass
class CryptoMapEntry:
    map_name: str
    seq: str
    peer: Optional[str] = None
    transform_sets: list = field(default_factory=list)
    acl: Optional[str] = None
    pfs: Optional[str] = None
    ikev2_profile: Optional[str] = None
    sa_lifetime: Optional[str] = None


@dataclass
class IpsecProfile:
    name: str
    transform_sets: list = field(default_factory=list)
    pfs: Optional[str] = None
    ikev2_profile: Optional[str] = None


@dataclass
class TunnelInterface:
    name: str
    ip_address: Optional[str] = None
    ip_mask: Optional[str] = None
    source: Optional[str] = None
    destination: Optional[str] = None
    mode: Optional[str] = None
    protection_profile: Optional[str] = None


@dataclass
class BgpNeighbor:
    ip: str
    remote_as: Optional[str] = None


# ---------------------------------------------------------------------------
# File-based config parser (unchanged from original)
# ---------------------------------------------------------------------------

class ConfigParser:
    """Parses IKEv1 objects from a running-config text file."""

    def __init__(self, text: str):
        self.lines = text.splitlines()
        self.isakmp_policies: list[IsakmpPolicy] = []
        self.isakmp_keys: list[IsakmpKey] = []
        self.transform_sets: dict[str, TransformSet] = {}
        self.crypto_maps: dict[tuple, CryptoMapEntry] = {}
        self.ipsec_profiles: dict[str, IpsecProfile] = {}
        self.tunnel_interfaces: dict[str, TunnelInterface] = {}
        self.bgp_neighbors: dict[str, BgpNeighbor] = {}
        self._parse()

    def _parse(self):
        i = 0
        while i < len(self.lines):
            line = self.lines[i].strip()

            m = re.match(r'^crypto isakmp policy\s+(\d+)', line)
            if m:
                policy = IsakmpPolicy(priority=m.group(1))
                i += 1
                while i < len(self.lines):
                    sub = self.lines[i].strip()
                    # IOS uses abbreviated 'encr'; IOS XE may use 'encryption'
                    if sub.startswith('encr ') or sub.startswith('encryption '):
                        policy.encryption = sub.split(None, 1)[1]  # captures "aes 256" etc.
                    elif sub.startswith('hash '):
                        policy.hash_alg = sub.split()[1]
                    elif sub.startswith('group '):
                        policy.group = sub.split()[1]
                    elif sub.startswith('lifetime '):
                        policy.lifetime = sub.split()[1]
                    elif sub.startswith('authentication '):
                        policy.auth = sub.split(None, 1)[1]
                    elif self._is_top_level_boundary(sub):
                        break
                    i += 1
                # Fill in IOS defaults for omitted lines — these are the values
                # in effect when the keyword does not appear in show run.
                # group2 is the default and is a FN72510 target — must not be missed.
                if policy.encryption is None:
                    policy.encryption = "aes"   # AES-128
                if policy.hash_alg is None:
                    policy.hash_alg = "sha"     # SHA-1
                if policy.group is None:
                    policy.group = "2"          # group2 — WEAK per FN72510
                self.isakmp_policies.append(policy)
                continue

            m = re.match(r'^crypto isakmp key\s+(\S+)\s+address\s+(\S+)(?:\s+(\S+))?', line)
            if m:
                self.isakmp_keys.append(IsakmpKey(
                    key=m.group(1), peer_ip=m.group(2), peer_mask=m.group(3)
                ))
                i += 1
                continue

            m = re.match(r'^crypto ipsec transform-set\s+(\S+)\s+(.*)', line)
            if m:
                name = m.group(1)
                transforms = m.group(2).strip().split()
                ts = TransformSet(name=name, transforms=transforms)
                i += 1
                while i < len(self.lines):
                    sub = self.lines[i].strip()
                    if sub.startswith('mode '):
                        ts.mode = sub.split()[1]
                    elif self._is_top_level_boundary(sub):
                        break
                    i += 1
                self.transform_sets[name] = ts
                continue


            m = re.match(r'^crypto ipsec profile\s+(\S+)', line)
            if m:
                name = m.group(1)
                prof = IpsecProfile(name=name)
                i += 1
                while i < len(self.lines):
                    sub = self.lines[i].strip()
                    if re.match(r'^set transform-set\s+', sub):
                        prof.transform_sets = sub.split()[2:]
                    elif re.match(r'^set pfs\s+', sub):
                        prof.pfs = sub.split()[-1]
                    elif re.match(r'^set ikev2-profile\s+', sub):
                        prof.ikev2_profile = sub.split()[-1]
                    elif self._is_top_level_boundary(sub):
                        break
                    i += 1
                self.ipsec_profiles[name] = prof
                continue

            m = re.match(r'^interface\s+(Tunnel\S+)', line, re.IGNORECASE)
            if m:
                name = m.group(1)
                tun = TunnelInterface(name=name)
                i += 1
                while i < len(self.lines):
                    sub = self.lines[i].strip()
                    if re.match(r'^ip address\s+', sub):
                        parts = sub.split()
                        if len(parts) >= 4:
                            tun.ip_address = parts[2]
                            tun.ip_mask = parts[3]
                    elif re.match(r'^tunnel source\s+', sub):
                        tun.source = sub.split(None, 2)[2]
                    elif re.match(r'^tunnel destination\s+', sub):
                        tun.destination = sub.split(None, 2)[2]
                    elif re.match(r'^tunnel mode\s+', sub):
                        tun.mode = sub.split(None, 2)[2]
                    elif re.match(r'^tunnel protection ipsec profile\s+', sub):
                        tun.protection_profile = sub.split()[-1]
                    elif self._is_top_level_boundary(sub):
                        break
                    i += 1
                self.tunnel_interfaces[name] = tun
                continue

            m = re.match(r'^router bgp\s+(\S+)', line)
            if m:
                i += 1
                while i < len(self.lines):
                    sub = self.lines[i].strip()
                    nm = re.match(r'^neighbor\s+(\S+)\s+remote-as\s+(\S+)', sub)
                    if nm:
                        ip, remote_as = nm.group(1), nm.group(2)
                        self.bgp_neighbors[ip] = BgpNeighbor(ip=ip, remote_as=remote_as)
                    elif self._is_top_level_boundary(sub):
                        break
                    i += 1
                continue

            m = re.match(r'^crypto map\s+(\S+)\s+(\d+)\s+ipsec-isakmp', line)
            if m:
                map_name, seq = m.group(1), m.group(2)
                entry = CryptoMapEntry(map_name=map_name, seq=seq)
                i += 1
                while i < len(self.lines):
                    sub = self.lines[i].strip()
                    if re.match(r'^set peer\s+', sub):
                        entry.peer = sub.split()[-1]
                    elif re.match(r'^set transform-set\s+', sub):
                        entry.transform_sets = sub.split()[2:]
                    elif re.match(r'^match address\s+', sub):
                        entry.acl = sub.split()[-1]
                    elif re.match(r'^set pfs\s+', sub):
                        entry.pfs = sub.split()[-1]
                    elif re.match(r'^set ikev2-profile\s+', sub):
                        entry.ikev2_profile = sub.split()[-1]
                    elif re.match(r'^set security-association lifetime\s+', sub):
                        entry.sa_lifetime = ' '.join(sub.split()[3:])
                    elif self._is_top_level_boundary(sub):
                        break
                    i += 1
                self.crypto_maps[(map_name, seq)] = entry
                continue

            i += 1

    @staticmethod
    def _is_top_level_boundary(line: str) -> bool:
        if not line or line.startswith('!'):
            return True
        return bool(re.match(r'^(crypto |interface |router |ip access-list |access-list |line |class-map |policy-map )', line))


# ---------------------------------------------------------------------------
# RESTCONF client
# ---------------------------------------------------------------------------

RESTCONF_BASE = "restconf/data"
CRYPTO_PATH   = "Cisco-IOS-XE-native:native/crypto"
NS_CRYPTO     = "Cisco-IOS-XE-crypto:"

RESTCONF_HEADERS = {
    "Accept":       "application/yang-data+json",
    "Content-Type": "application/yang-data+json",
}


class RestconfClient:
    """Thin HTTPS wrapper for IOS XE RESTCONF."""

    def __init__(self, host: str, username: str, password: str,
                 port: int = 443, verify_ssl: bool = True):
        if requests is None:
            raise RuntimeError("requests package required for device mode: pip install requests")
        self.base_url = f"https://{host}:{port}/{RESTCONF_BASE}"
        self.auth     = HTTPBasicAuth(username, password)
        self.verify   = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get(self, path: str) -> Optional[dict]:
        url = f"{self.base_url}/{path}"
        log.debug("GET %s", url)
        r = requests.get(url, auth=self.auth, headers=RESTCONF_HEADERS,
                         verify=self.verify, timeout=30)
        if r.status_code == 204:
            return {}
        r.raise_for_status()
        return r.json()

    def patch(self, path: str, payload: dict) -> None:
        url = f"{self.base_url}/{path}"
        log.debug("PATCH %s\n%s", url, json.dumps(payload, indent=2))
        r = requests.patch(url, auth=self.auth, headers=RESTCONF_HEADERS,
                           json=payload, verify=self.verify, timeout=30)
        if r.status_code not in (200, 201, 204):
            log.error("PATCH failed %d: %s", r.status_code, r.text[:500])
            r.raise_for_status()

    def put(self, path: str, payload: dict) -> None:
        url = f"{self.base_url}/{path}"
        log.debug("PUT %s", url)
        r = requests.put(url, auth=self.auth, headers=RESTCONF_HEADERS,
                         json=payload, verify=self.verify, timeout=30)
        if r.status_code not in (200, 201, 204):
            log.error("PUT failed %d: %s", r.status_code, r.text[:500])
            r.raise_for_status()


# ---------------------------------------------------------------------------
# RESTCONF config parser — produces same data structures as ConfigParser
# ---------------------------------------------------------------------------

class RestconfConfigParser:
    """
    Reads crypto config from a live device via RESTCONF and populates
    the same isakmp_policies / isakmp_keys / transform_sets / crypto_maps
    attributes that ConfigParser produces, so IKEv2ConfigGenerator can
    consume either parser without modification.
    """

    def __init__(self, client: RestconfClient):
        self.isakmp_policies: list[IsakmpPolicy] = []
        self.isakmp_keys:     list[IsakmpKey]    = []
        self.transform_sets:  dict[str, TransformSet]      = {}
        self.crypto_maps:     dict[tuple, CryptoMapEntry]  = {}
        self.ipsec_profiles:  dict[str, IpsecProfile]      = {}
        self.tunnel_interfaces: dict[str, TunnelInterface] = {}
        self.bgp_neighbors:   dict[str, BgpNeighbor]       = {}
        self._raw: dict = {}
        self._fetch(client)

    def _fetch(self, client: RestconfClient):
        data = client.get(CRYPTO_PATH) or {}
        # unwrap top-level namespace
        crypto = data.get("Cisco-IOS-XE-native:crypto", data)
        self._raw = crypto
        isakmp  = crypto.get(f"{NS_CRYPTO}isakmp", crypto.get("Cisco-IOS-XE-crypto:isakmp", {}))
        ipsec   = crypto.get(f"{NS_CRYPTO}ipsec",  crypto.get("Cisco-IOS-XE-crypto:ipsec",  {}))
        cmap    = crypto.get(f"{NS_CRYPTO}map",    crypto.get("Cisco-IOS-XE-crypto:map",    {}))
        self._parse_isakmp_policies(isakmp.get("policy", []))
        self._parse_isakmp_keys(isakmp.get("key", {}))
        self._parse_transform_sets(ipsec.get("transform-set", []))
        self._parse_crypto_maps(cmap)

    # ---- isakmp policies ----

    def _parse_isakmp_policies(self, policies: list):
        for p in policies:
            policy = IsakmpPolicy(priority=str(p.get("number", "")))
            policy.authentication = p.get("authentication")
            policy.hash_alg       = p.get("hash")
            policy.group          = str(p["group"]) if "group" in p else None
            policy.lifetime       = str(p["lifetime"]) if "lifetime" in p else None
            enc = p.get("encryption", {})
            policy.encryption     = self._parse_isakmp_enc(enc)
            self.isakmp_policies.append(policy)

    @staticmethod
    def _parse_isakmp_enc(enc: dict) -> Optional[str]:
        if not enc:
            return None
        if "a3des" in enc:
            return "3des"
        if "des-choice" in enc:
            return "des"
        # aes-256 / aes-192 direct leaves
        for leaf, name in (("aes-256", "aes 256"), ("aes-192", "aes 192")):
            if leaf in enc:
                return name
        # aes-choice container with key-type sub-leaf
        aes = enc.get("aes-choice", {})
        if aes:
            bits = aes.get("key-type", "128")
            return f"aes {bits}"
        return None

    # ---- isakmp pre-shared keys ----

    def _parse_isakmp_keys(self, key_root: dict):
        if not key_root:
            return
        # IOS XE YANG models isakmp keys as a single container (not a list)
        # which reflects that RESTCONF typically shows only one entry.
        # In practice, production devices with multiple peers may return a list
        # variant; handle both.
        entries = key_root if isinstance(key_root, list) else [key_root]
        for entry in entries:
            ka = entry.get("key-address", {})
            if not ka:
                continue
            key_val = ka.get("key", "<PSK_OBFUSCATED_REPLACE_ME>")
            enc_type = ka.get("encryption")
            if enc_type and str(enc_type) == "6":
                key_val = "<PSK_TYPE6_ENCRYPTED_REPLACE_ME>"
            ipv4_container = ka.get("addr4-container", {})
            peer_ip   = ipv4_container.get("address")
            peer_mask = ipv4_container.get("mask")
            if peer_ip:
                self.isakmp_keys.append(IsakmpKey(
                    key=key_val, peer_ip=peer_ip, peer_mask=peer_mask
                ))

    # ---- ipsec transform-sets ----

    def _parse_transform_sets(self, ts_list: list):
        for ts in ts_list:
            name      = ts.get("tag", "")
            transforms = self._ts_transforms(ts)
            mode       = self._ts_mode(ts)
            self.transform_sets[name] = TransformSet(
                name=name, transforms=transforms, mode=mode
            )

    @staticmethod
    def _ts_transforms(ts: dict) -> list:
        parts = []
        esp = ts.get("esp")
        if esp:
            parts.append(esp)
            key_bit = ts.get("key-bit")
            if key_bit:
                parts.append(str(key_bit))
            hmac = ts.get("esp-hmac")
            if hmac:
                parts.append(hmac)
        ah = ts.get("ah-hmac")
        if ah:
            parts.append(ah)
        return parts

    @staticmethod
    def _ts_mode(ts: dict) -> Optional[str]:
        mode_obj = ts.get("mode", {})
        if not mode_obj:
            return None
        if "transport-choice" in mode_obj:
            return "transport"
        if "tunnel-choice" in mode_obj:
            return "tunnel"
        # deprecated leaves
        if "transport" in mode_obj:
            return "transport"
        if mode_obj.get("tunnel"):
            return "tunnel"
        return None

    # ---- crypto maps ----

    def _parse_crypto_maps(self, cmap_root: dict):
        if not cmap_root:
            return
        map_seq = cmap_root.get("map-seq", {})
        entries = map_seq.get("map", [])
        for m in entries:
            map_name = m.get("name", "")
            seq      = str(m.get("seq", ""))
            isakmp   = m.get("ipsec-isakmp", {})
            if not isakmp:
                continue
            set_obj  = isakmp.get("set", {})
            match_obj= isakmp.get("match", {})
            entry = CryptoMapEntry(map_name=map_name, seq=seq)
            peer_c = set_obj.get("peer", {})
            entry.peer             = peer_c.get("address") if isinstance(peer_c, dict) else None
            entry.transform_sets   = list(set_obj.get("transform-set", []))
            entry.acl              = match_obj.get("address")
            pfs_c  = set_obj.get("pfs", {})
            entry.pfs              = pfs_c.get("group") if pfs_c else None
            entry.ikev2_profile    = set_obj.get("ikev2-profile")
            sa_c = set_obj.get("security-association", {})
            lt   = sa_c.get("lifetime", {}) if sa_c else {}
            if lt:
                secs = lt.get("seconds")
                if secs:
                    entry.sa_lifetime = f"seconds {secs}"
            self.crypto_maps[(map_name, seq)] = entry


# ---------------------------------------------------------------------------
# Text-mode config generator (unchanged logic, updated constants)
# ---------------------------------------------------------------------------

class IKEv2ConfigGenerator:
    def __init__(self, parsed, aws_peer_filter: Optional[str] = None):
        self.p = parsed
        self.aws_peer_filter = aws_peer_filter
        self.warnings: list[str] = []
        self.output_lines: list[str] = []

    def _warn(self, msg: str):
        self.warnings.append(msg)

    def _emit(self, line: str = ""):
        self.output_lines.append(line)

    def _target_entries(self) -> list[CryptoMapEntry]:
        targets = []
        for entry in self.p.crypto_maps.values():
            if entry.ikev2_profile:
                continue
            if self.aws_peer_filter and entry.peer != self.aws_peer_filter:
                continue
            targets.append(entry)
        return targets

    def _target_vti_tunnels(self) -> list[TunnelInterface]:
        targets = []
        for tun in getattr(self.p, "tunnel_interfaces", {}).values():
            if not tun.destination or not tun.protection_profile:
                continue
            prof = getattr(self.p, "ipsec_profiles", {}).get(tun.protection_profile)
            if not prof or prof.ikev2_profile:
                continue
            if self.aws_peer_filter and tun.destination != self.aws_peer_filter:
                continue
            targets.append(tun)
        return targets

    def _peer_ips_for_targets(self, entries: list[CryptoMapEntry],
                              tunnels: list[TunnelInterface]) -> set[str]:
        return {e.peer for e in entries if e.peer} | {t.destination for t in tunnels if t.destination}

    def _peers_for_entries(self, entries: list[CryptoMapEntry]) -> list[IsakmpKey]:
        """Compatibility helper for RESTCONF crypto-map payload builder."""
        return self._peers_for_targets(entries, [])

    def _peers_for_targets(self, entries: list[CryptoMapEntry],
                           tunnels: list[TunnelInterface]) -> list[IsakmpKey]:
        peer_ips = self._peer_ips_for_targets(entries, tunnels)
        matched, seen = [], set()
        for key in self.p.isakmp_keys:
            if key.peer_ip in peer_ips and key.peer_ip not in seen:
                matched.append(key)
                seen.add(key.peer_ip)
        for ip in sorted(peer_ips):
            if ip not in seen:
                self._warn(
                    f"Peer {ip} has no matching 'crypto isakmp key' entry. "
                    f"Supply the PSK manually in the generated keyring."
                )
                matched.append(IsakmpKey(key="<PSK_UNKNOWN_REPLACE_ME>", peer_ip=ip))
                seen.add(ip)
        return matched

    def _weak_transform_sets(self, entries: list[CryptoMapEntry],
                             tunnels: list[TunnelInterface] | None = None) -> dict[str, TransformSet]:
        used = set()
        for e in entries:
            used.update(e.transform_sets)
        for tun in tunnels or []:
            prof = getattr(self.p, "ipsec_profiles", {}).get(tun.protection_profile or "")
            if prof:
                used.update(prof.transform_sets)
        return {n: self.p.transform_sets[n] for n in used
                if n in self.p.transform_sets and self.p.transform_sets[n].has_weak_algo()}

    def generate(self) -> str:
        targets = self._target_entries()
        vti_targets = self._target_vti_tunnels()
        if not targets and not vti_targets:
            return (
                "! --- No crypto map entries requiring IKEv2 migration found; no VTI/IPsec profile entries requiring migration found.\n"
                "! --- (All entries either already have ikev2-profile set, or\n"
                "!     no matching peer filter was found.)\n"
            )
        peers   = self._peers_for_targets(targets, vti_targets)
        weak_ts = self._weak_transform_sets(targets, vti_targets)

        self._emit("! ================================================================")
        self._emit("! IKEv2 Migration Config — generated by ikev1_to_ikev2_migrate.py")
        self._emit("! IOS XE 17.11+ / FN72510 compliant")
        self._emit("! Platform: ISR4431, IOS XE 17.09.05a")
        self._emit("! Algorithms: AES-CBC-256 / SHA-512 / DH group 21 / PFS group21")
        self._emit("! IKEv1 config left in place — additive migration, full rollback possible.")
        self._emit("! Review all PSKs before applying. Test in a maintenance window.")
        self._emit("! ================================================================")
        self._emit()
        self._gen_proposal()
        self._gen_policy()
        self._gen_keyring(peers)
        self._gen_profile(peers)
        self._gen_transform_sets(weak_ts)
        if targets:
            self._gen_crypto_map_updates(targets, weak_ts)
        if vti_targets:
            self._gen_vti_profile_updates(vti_targets, weak_ts)
            self._gen_bgp_notes(vti_targets)
        self._gen_fragmentation()
        if self.warnings:
            self._emit()
            self._emit("! ================================================================")
            self._emit("! WARNINGS — manual review required:")
            for w in self.warnings:
                self._emit(f"!   * {w}")
            self._emit("! ================================================================")
        return "\n".join(self.output_lines)

    def _gen_proposal(self):
        self._emit("! ---- IKEv2 Proposal (Phase 1 algorithms) ----")
        self._emit("! AES-CBC-256 confirmed available on ISR4431/17.09.05a (GCM is not).")
        self._emit("! SHA-512 integrity required when using CBC encryption.")
        self._emit("! DH group 21 = 521-bit ECP (highest available on this image).")
        self._emit("crypto ikev2 proposal AWS-IKEV2-PROPOSAL")
        self._emit(f" encryption {MODERN_IKE_ENCRYPTION}")
        self._emit(f" integrity {MODERN_IKE_INTEGRITY}")
        self._emit(f" prf {MODERN_IKE_PRF}")
        self._emit(f" group {MODERN_IKE_DH_GROUP}")
        self._emit("!")

    def _gen_policy(self):
        self._emit("! ---- IKEv2 Policy ----")
        self._emit("crypto ikev2 policy AWS-IKEV2-POLICY")
        self._emit(" match fvrf any")
        self._emit(" proposal AWS-IKEV2-PROPOSAL")
        self._emit("!")

    def _gen_keyring(self, peers: list[IsakmpKey]):
        self._emit("! ---- IKEv2 Keyring ----")
        self._emit("! Standard AWS S2S VPN uses the same PSK for local and remote on each tunnel.")
        self._emit("! Replace the pre-shared-key values with those from the")
        self._emit("! AWS VPN configuration download for each tunnel endpoint.")
        self._emit("crypto ikev2 keyring AWS-IKEV2-KEYRING")
        for key in peers:
            peer_name = "PEER-" + key.peer_ip.replace(".", "-")
            self._emit(f" peer {peer_name}")
            self._emit(f"  address {key.peer_ip}")
            if key.peer_mask:
                self._emit(f"  ! (original isakmp key used mask {key.peer_mask})")
            self._emit(f"  pre-shared-key local {key.key}")
            self._emit(f"  pre-shared-key remote {key.key}")
            self._emit(f" !")
        self._emit("!")

    def _gen_profile(self, peers: list[IsakmpKey]):
        self._emit("! ---- IKEv2 Profile ----")
        self._emit("! 'match identity remote address 0.0.0.0' matches any peer in the keyring.")
        self._emit(f"! SA lifetime set to {AWS_SA_LIFETIME}s (8h) to match AWS default.")
        self._emit("! DPD: 10s interval, 3 retries, periodic mode (matches AWS DPD 30s/clear).")
        self._emit("crypto ikev2 profile AWS-IKEV2-PROFILE")
        self._emit(" match identity remote address 0.0.0.0")
        self._emit(" ! identity local address <YOUR-WAN-INTERFACE-IP>")
        self._emit(" authentication remote pre-share")
        self._emit(" authentication local pre-share")
        self._emit(" keyring local AWS-IKEV2-KEYRING")
        self._emit(" dpd 10 3 periodic")
        self._emit(f" lifetime {AWS_SA_LIFETIME}")
        self._emit("!")

    def _gen_transform_sets(self, weak_ts: dict[str, TransformSet]):
        if not weak_ts:
            self._emit("! ---- No weak transform-sets found in migrated entries ----")
            self._emit("!")
            return
        self._emit("! ---- Replacement transform-sets (FN72510 remediation) ----")
        self._emit("! esp-aes 256 esp-sha512-hmac confirmed available on ISR4431/17.09.05a.")
        self._emit("! New sets named <original>-V2 to avoid colliding with existing IKEv1 sets.")
        for name, ts in weak_ts.items():
            new_name = f"{name}-V2"
            self._emit(f"! Replacing: crypto ipsec transform-set {name} {' '.join(ts.transforms)}")
            self._emit(f"crypto ipsec transform-set {new_name} "
                       f"{MODERN_ESP_ENC} {MODERN_ESP_KEY_BIT} {MODERN_ESP_HMAC}")
            if ts.mode in ("tunnel", "transport"):
                self._emit(f" mode {ts.mode}")
            self._emit("!")

    def _gen_crypto_map_updates(self, targets: list[CryptoMapEntry],
                                weak_ts: dict[str, TransformSet]):
        self._emit("! ---- Crypto map updates ----")
        self._emit("! set ikev2-profile added; weak transform-sets replaced with -V2 equivalents;")
        self._emit("! weak PFS groups updated to group21. IKEv1 entries preserved for rollback.")
        self._emit()
        by_map: dict[str, list[CryptoMapEntry]] = {}
        for e in targets:
            by_map.setdefault(e.map_name, []).append(e)
        for map_name, entries in by_map.items():
            for entry in sorted(entries, key=lambda x: int(x.seq)):
                self._emit(f"crypto map {map_name} {entry.seq} ipsec-isakmp")
                new_ts = [f"{n}-V2" if n in weak_ts else n for n in entry.transform_sets]
                if new_ts:
                    self._emit(f" set transform-set {' '.join(new_ts)}")
                if entry.pfs and entry.pfs.lower() in WEAK_PFS_GROUPS:
                    self._emit(f" ! replacing weak PFS {entry.pfs}")
                    self._emit(f" set pfs {MODERN_PFS_GROUP}")
                elif entry.pfs:
                    self._emit(f" set pfs {entry.pfs}")
                else:
                    self._emit(f" set pfs {MODERN_PFS_GROUP}")
                self._emit(" set ikev2-profile AWS-IKEV2-PROFILE")
                self._emit("!")


    def _gen_vti_profile_updates(self, tunnels: list[TunnelInterface],
                                 weak_ts: dict[str, TransformSet]):
        self._emit("! ---- VTI / crypto ipsec profile updates ----")
        self._emit("! Route-based VPNs keep Tunnel interfaces and BGP unchanged.")
        self._emit("! The IKEv2 binding belongs under the crypto ipsec profile used by tunnel protection.")
        self._emit()
        seen_profiles = set()
        for tun in sorted(tunnels, key=lambda t: t.name):
            prof = self.p.ipsec_profiles.get(tun.protection_profile or "")
            if not prof or prof.name in seen_profiles:
                continue
            seen_profiles.add(prof.name)
            self._emit(f"! {tun.name}: destination {tun.destination}, tunnel protection ipsec profile {prof.name}")
            self._emit(f"crypto ipsec profile {prof.name}")
            new_ts = [f"{n}-V2" if n in weak_ts else n for n in prof.transform_sets]
            if new_ts:
                self._emit(f" set transform-set {' '.join(new_ts)}")
            if prof.pfs and prof.pfs.lower() in WEAK_PFS_GROUPS:
                self._emit(f" ! replacing weak PFS {prof.pfs}")
                self._emit(f" set pfs {MODERN_PFS_GROUP}")
            elif prof.pfs:
                self._emit(f" set pfs {prof.pfs}")
            else:
                self._emit(f" set pfs {MODERN_PFS_GROUP}")
            self._emit(" set ikev2-profile AWS-IKEV2-PROFILE")
            self._emit("!")

    def _gen_bgp_notes(self, tunnels: list[TunnelInterface]):
        if not getattr(self.p, "bgp_neighbors", {}):
            return
        tunnel_ips = {t.ip_address for t in tunnels if t.ip_address}
        neighbors = []
        for nbr in self.p.bgp_neighbors.values():
            neighbors.append(f"{nbr.ip} remote-as {nbr.remote_as}")
        self._emit("! ---- BGP over VTI review ----")
        self._emit("! BGP config is intentionally not changed by IKEv1→IKEv2 migration.")
        self._emit("! Confirm AWS inside tunnel IPs / BGP neighbors remain unchanged after tunnel rekeys.")
        if tunnel_ips:
            self._emit(f"! Local tunnel IPs detected: {', '.join(sorted(tunnel_ips))}")
        self._emit(f"! BGP neighbors detected: {', '.join(sorted(neighbors))}")
        self._emit("!")

    def _gen_fragmentation(self):
        self._emit("! ---- IKEv2 fragmentation ----")
        self._emit("! Prevents auth payload fragmentation issues with MTU-strict underlays.")
        self._emit("crypto ikev2 fragmentation mtu 1200")
        self._emit("!")


# ---------------------------------------------------------------------------
# YANG JSON payload builder (for RESTCONF PATCH)
# ---------------------------------------------------------------------------

class IKEv2JsonPayloadBuilder:
    """
    Builds YANG-compliant JSON payloads for RESTCONF PATCH.
    Mirrors IKEv2ConfigGenerator but produces structured data instead of text.
    """

    def __init__(self, parsed, aws_peer_filter: Optional[str] = None):
        self._gen = IKEv2ConfigGenerator(parsed, aws_peer_filter)
        self.targets  = self._gen._target_entries()
        self.peers    = self._gen._peers_for_entries(self.targets)
        self.weak_ts  = self._gen._weak_transform_sets(self.targets)
        self.warnings = self._gen.warnings

    def build_proposal(self) -> dict:
        return {
            "name": "AWS-IKEV2-PROPOSAL",
            "encryption": {"aes-cbc-256": [None]},
            "integrity":  {"sha512": [None]},
            "prf":        {"sha512": [None]},
            "group":      {"twenty-one": [None]},
        }

    def build_policy(self) -> dict:
        return {
            "name": "AWS-IKEV2-POLICY",
            "match": {"fvrf": {"any": [None]}},
            "proposal": [{"proposals": "AWS-IKEV2-PROPOSAL"}],
        }

    def build_keyring(self) -> dict:
        peers_json = []
        for key in self.peers:
            peer_name = "PEER-" + key.peer_ip.replace(".", "-")
            peer_entry: dict = {
                "name": peer_name,
                "address": {
                    "ipv4": {
                        "ipv4-address": key.peer_ip,
                        "ipv4-mask": key.peer_mask or "255.255.255.255",
                    }
                },
                "pre-shared-key": {
                    "local-option":  {"key": key.key},
                    "remote-option": {"key": key.key},
                },
            }
            peers_json.append(peer_entry)
        return {"name": "AWS-IKEV2-KEYRING", "peer": peers_json}

    def build_profile(self) -> dict:
        return {
            "name": "AWS-IKEV2-PROFILE",
            "match": {
                "identity": {
                    "remote": {
                        "address": {
                            "ipv4": [
                                {"ipv4-address": "0.0.0.0", "ipv4-mask": "0.0.0.0"}
                            ]
                        }
                    }
                },
                "fvrf": {"any": [None]},
            },
            "authentication": {
                "local":  {"pre-share": {}},
                "remote": {"pre-share": {}},
            },
            "keyring": {"local": {"name": "AWS-IKEV2-KEYRING"}},
            "dpd": {
                "interval": 10,
                "retry": 3,
                "query": "periodic",
            },
            "lifetime": {"seconds": AWS_SA_LIFETIME},
        }

    def build_transform_sets(self) -> list:
        result = []
        for name, ts in self.weak_ts.items():
            entry: dict = {
                "tag":      f"{name}-V2",
                "esp":      MODERN_ESP_ENC,
                "key-bit":  MODERN_ESP_KEY_BIT,
                "esp-hmac": MODERN_ESP_HMAC,
            }
            mode = ts.mode
            if mode == "tunnel":
                entry["mode"] = {"tunnel-choice": [None]}
            elif mode == "transport":
                entry["mode"] = {"transport-choice": {}}
            result.append(entry)
        return result

    def build_crypto_map_patches(self) -> list[tuple[str, dict]]:
        """
        Returns a list of (restconf_path, payload) tuples — one per crypto map entry.
        Each PATCH targets the entry's set container to add ikev2-profile and update
        transform-set / pfs without overwriting peer or match/address.
        """
        patches = []
        for entry in self.targets:
            new_ts = [f"{n}-V2" if n in self.weak_ts else n for n in entry.transform_sets]
            if entry.pfs and entry.pfs.lower() in WEAK_PFS_GROUPS:
                new_pfs = MODERN_PFS_GROUP
            elif entry.pfs:
                new_pfs = entry.pfs
            else:
                new_pfs = MODERN_PFS_GROUP

            set_payload: dict = {
                "ikev2-profile": "AWS-IKEV2-PROFILE",
                "pfs": {"group": new_pfs},
            }
            if new_ts:
                set_payload["transform-set"] = new_ts

            # Path targets the set container of this specific map entry
            path = (
                f"{CRYPTO_PATH}/{NS_CRYPTO}map/map-seq/map="
                f"{entry.map_name},{entry.seq}/ipsec-isakmp/set"
            )
            patches.append((path, {"Cisco-IOS-XE-crypto:set": set_payload}))
        return patches

    def build_ikev2_patch_payload(self) -> dict:
        """
        Builds the full PATCH payload for the ikev2 sub-tree
        (proposal + policy + keyring + profile in one request).
        """
        return {
            f"{NS_CRYPTO}ikev2": {
                "proposal": [self.build_proposal()],
                "policy":   [self.build_policy()],
                "keyring":  [self.build_keyring()],
                "profile":  [self.build_profile()],
            }
        }

    def build_ipsec_transform_patch_payload(self) -> Optional[dict]:
        ts_list = self.build_transform_sets()
        if not ts_list:
            return None
        return {f"{NS_CRYPTO}ipsec": {"transform-set": ts_list}}


# ---------------------------------------------------------------------------
# RESTCONF migration orchestrator
# ---------------------------------------------------------------------------

class RestconfMigrator:
    """
    Orchestrates the full GET → parse → generate → PATCH → validate cycle.
    """

    def __init__(self, client: RestconfClient, aws_peer_filter: Optional[str] = None,
                 dry_run: bool = False, audit_only: bool = False,
                 ssh_username: Optional[str] = None, ssh_password: Optional[str] = None,
                 ssh_host: Optional[str] = None):
        self.client           = client
        self.aws_peer_filter  = aws_peer_filter
        self.dry_run          = dry_run
        self.audit_only       = audit_only
        self.ssh_username     = ssh_username
        self.ssh_password     = ssh_password
        self.ssh_host         = ssh_host

    def run(self) -> int:
        """Returns 0 on success, 1 on error."""
        print("[ RESTCONF ] Fetching current crypto config...")
        try:
            parsed = RestconfConfigParser(self.client)
        except Exception as exc:
            print(f"[ERROR] Failed to fetch config: {exc}", file=sys.stderr)
            return 1

        gen = IKEv2ConfigGenerator(parsed, self.aws_peer_filter)
        targets = gen._target_entries()

        print(validation_report(parsed, targets))

        if self.audit_only:
            return 0

        if not targets:
            return 0

        builder = IKEv2JsonPayloadBuilder(parsed, self.aws_peer_filter)

        if builder.warnings:
            for w in builder.warnings:
                print(f"[WARN] {w}")

        # ---- show what will be patched ----
        ikev2_payload  = builder.build_ikev2_patch_payload()
        ipsec_payload  = builder.build_ipsec_transform_patch_payload()
        map_patches    = builder.build_crypto_map_patches()

        if self.dry_run:
            print("\n[ DRY-RUN ] The following payloads would be PATCHed:\n")
            print(f"  PATH: {CRYPTO_PATH}")
            print(json.dumps(ikev2_payload, indent=2))
            if ipsec_payload:
                print(f"\n  PATH: {CRYPTO_PATH}")
                print(json.dumps(ipsec_payload, indent=2))
            for path, payload in map_patches:
                print(f"\n  PATH: {path}")
                print(json.dumps(payload, indent=2))
            return 0

        # ---- apply ----
        try:
            print("[ RESTCONF ] Patching IKEv2 proposal / policy / keyring / profile...")
            self.client.patch(CRYPTO_PATH, ikev2_payload)

            if ipsec_payload:
                print("[ RESTCONF ] Patching replacement transform-sets...")
                self.client.patch(CRYPTO_PATH, ipsec_payload)

            print("[ RESTCONF ] Patching crypto map entries...")
            for path, payload in map_patches:
                self.client.patch(path, payload)

            print("[ RESTCONF ] All PATCHes accepted.")
        except Exception as exc:
            print(f"[ERROR] PATCH failed: {exc}", file=sys.stderr)
            return 1

        # ---- validate ----
        return self._validate(parsed)

    def _validate(self, original_parsed) -> int:
        print("\n[ VALIDATE ] Verifying IKEv2 objects via RESTCONF GET...")
        try:
            data = self.client.get(f"{CRYPTO_PATH}/{NS_CRYPTO}ikev2") or {}
            ikev2 = data.get("Cisco-IOS-XE-crypto:ikev2", {})

            proposals = ikev2.get("proposal", [])
            policies  = ikev2.get("policy",   [])
            keyrings  = ikev2.get("keyring",  [])
            profiles  = ikev2.get("profile",  [])

            prop_names    = [p.get("name") for p in proposals]
            policy_names  = [p.get("name") for p in policies]
            keyring_names = [k.get("name") for k in keyrings]
            profile_names = [p.get("name") for p in profiles]

            ok = True
            for obj, name, found in [
                ("proposal", "AWS-IKEV2-PROPOSAL", "AWS-IKEV2-PROPOSAL" in prop_names),
                ("policy",   "AWS-IKEV2-POLICY",   "AWS-IKEV2-POLICY"   in policy_names),
                ("keyring",  "AWS-IKEV2-KEYRING",  "AWS-IKEV2-KEYRING"  in keyring_names),
                ("profile",  "AWS-IKEV2-PROFILE",  "AWS-IKEV2-PROFILE"  in profile_names),
            ]:
                status = "OK" if found else "MISSING"
                print(f"  IKEv2 {obj:12s} {name:<25s} [{status}]")
                if not found:
                    ok = False
        except Exception as exc:
            print(f"[WARN] RESTCONF validation GET failed: {exc}")
            ok = False

        # ---- netmiko SA check ----
        if ConnectHandler and self.ssh_host and self.ssh_username and self.ssh_password:
            print("\n[ VALIDATE ] Checking IKEv2 SA state via SSH...")
            try:
                dev = dict(
                    device_type="cisco_ios",
                    host=self.ssh_host,
                    username=self.ssh_username,
                    password=self.ssh_password,
                )
                with ConnectHandler(**dev) as conn:
                    sa_output = conn.send_command("show crypto ikev2 sa")
                    print(sa_output)
            except Exception as exc:
                print(f"[WARN] SSH validation failed: {exc}")
        elif not ConnectHandler:
            print("[INFO] netmiko not installed — skipping 'show crypto ikev2 sa' check.")

        if ok:
            print("\n[ VALIDATE ] IKEv2 objects confirmed on device.")
        else:
            print("\n[WARN] One or more expected IKEv2 objects not found after PATCH.")
            return 1
        return 0


# ---------------------------------------------------------------------------
# Audit / validation report (shared by both modes)
# ---------------------------------------------------------------------------

def validation_report(parsed, targets: list[CryptoMapEntry]) -> str:
    lines = []
    lines.append("! ================================================================")
    lines.append("! PRE-MIGRATION AUDIT REPORT")
    lines.append("! ================================================================")
    lines.append("!")
    lines.append(f"! IKEv1 ISAKMP policies found: {len(parsed.isakmp_policies)}")
    for p in parsed.isakmp_policies:
        weak_flags = []
        if p.encryption in WEAK_ISAKMP_ENCRYPTION:
            weak_flags.append(f"WEAK-ENC:{p.encryption}")
        if p.hash_alg in WEAK_ISAKMP_HASH:
            weak_flags.append(f"WEAK-HASH:{p.hash_alg}")
        if p.group in WEAK_ISAKMP_GROUPS:
            weak_flags.append(f"WEAK-GROUP:{p.group}")
        flag_str = f"  *** {', '.join(weak_flags)}" if weak_flags else "  (algorithms OK for 17.11+)"
        lines.append(f"!   Policy {p.priority}: enc={p.encryption} hash={p.hash_alg} "
                     f"group={p.group}{flag_str}")
    lines.append("!")
    lines.append(f"! IKEv1 pre-shared keys: {len(parsed.isakmp_keys)}")
    for k in parsed.isakmp_keys:
        lines.append(f"!   Peer {k.peer_ip}")
    lines.append("!")
    lines.append(f"! Transform-sets: {len(parsed.transform_sets)}")
    for name, ts in parsed.transform_sets.items():
        weak = " *** WEAK" if ts.has_weak_algo() else ""
        lines.append(f"!   {name}: {' '.join(ts.transforms)}{weak}")
    lines.append("!")
    lines.append(f"! Crypto map entries targeted for migration: {len(targets)}")
    for e in targets:
        lines.append(f"!   {e.map_name} seq {e.seq}: peer={e.peer} "
                     f"ts={e.transform_sets} pfs={e.pfs}")
    vti_targets = IKEv2ConfigGenerator(parsed)._target_vti_tunnels()
    lines.append(f"! VTI/IPsec profile entries targeted for migration: {len(vti_targets)}")
    for t in vti_targets:
        prof = parsed.ipsec_profiles.get(t.protection_profile) if hasattr(parsed, "ipsec_profiles") else None
        lines.append(f"!   {t.name}: peer={t.destination} profile={t.protection_profile} "
                     f"ts={prof.transform_sets if prof else []} pfs={prof.pfs if prof else None}")
    if getattr(parsed, "bgp_neighbors", {}):
        lines.append("! BGP neighbors detected over/near tunnel config; BGP is not modified:")
        for n in parsed.bgp_neighbors.values():
            lines.append(f"!   neighbor {n.ip} remote-as {n.remote_as}")
    lines.append("!")
    lines.append("! ================================================================")
    lines.append("!")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Migrate Cisco IOS XE IKEv1 IPsec to IKEv2 (FN72510 compliant).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # File mode — generate config to paste
  %(prog)s --config-file running.cfg --aws-peer 169.254.1.1

  # Device mode — full RESTCONF workflow (dry-run first)
  %(prog)s --device 192.0.2.1 --username admin --password secret --dry-run

  # Device mode — apply changes and validate
  %(prog)s --device 192.0.2.1 --username admin --password secret --aws-peer 169.254.1.1
"""
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config-file", metavar="FILE",
                        help="Path to startup-config or running-config text file")
    source.add_argument("--device", metavar="HOST",
                        help="Device hostname or IP for RESTCONF mode")

    parser.add_argument("--username", metavar="USER",
                        help="RESTCONF/SSH username (device mode)")
    parser.add_argument("--password", metavar="PASS",
                        help="RESTCONF/SSH password (device mode)")
    parser.add_argument("--port", metavar="N", type=int, default=443,
                        help="RESTCONF HTTPS port (default: 443)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable TLS certificate verification")

    parser.add_argument("--aws-peer", metavar="IP",
                        help="Restrict migration to crypto map entries matching this peer IP")
    parser.add_argument("--audit-only", action="store_true",
                        help="Print audit report only; do not generate or apply config")
    parser.add_argument("--dry-run", action="store_true",
                        help="(Device mode) Show RESTCONF payloads without applying them")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(levelname)s %(message)s")

    # ---- FILE MODE ----
    if args.config_file:
        try:
            with open(args.config_file) as f:
                config_text = f.read()
        except FileNotFoundError:
            print(f"Error: file not found: {args.config_file}", file=sys.stderr)
            sys.exit(1)

        parsed  = ConfigParser(config_text)
        gen     = IKEv2ConfigGenerator(parsed, aws_peer_filter=args.aws_peer)
        targets = gen._target_entries()

        print(validation_report(parsed, targets))
        if not args.audit_only:
            print(gen.generate())
        return

    # ---- DEVICE MODE ----
    if not args.username or not args.password:
        print("Error: --username and --password are required in device mode.", file=sys.stderr)
        sys.exit(1)

    client = RestconfClient(
        host=args.device,
        username=args.username,
        password=args.password,
        port=args.port,
        verify_ssl=not args.no_verify_ssl,
    )

    migrator = RestconfMigrator(
        client=client,
        aws_peer_filter=args.aws_peer,
        dry_run=args.dry_run,
        audit_only=args.audit_only,
        ssh_host=args.device,
        ssh_username=args.username,
        ssh_password=args.password,
    )
    sys.exit(migrator.run())


if __name__ == "__main__":
    main()
