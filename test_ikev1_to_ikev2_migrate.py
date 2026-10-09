#!/usr/bin/env python3
"""
Tests for ikev1_to_ikev2_migrate.py

Run with:  python3 -m pytest test_ikev1_to_ikev2_migrate.py -v
       or: python3 test_ikev1_to_ikev2_migrate.py

No network access required.  All fixtures are static config snippets
derived from real device output observed during lab validation.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ikev1_to_ikev2_migrate import (
    ConfigParser,
    IsakmpPolicy,
    IsakmpKey,
    TransformSet,
    CryptoMapEntry,
    IKEv2ConfigGenerator,
    IKEv2JsonPayloadBuilder,
    validation_report,
    MODERN_IKE_ENCRYPTION,
    MODERN_IKE_INTEGRITY,
    MODERN_IKE_DH_GROUP,
    MODERN_ESP_ENC,
    MODERN_ESP_KEY_BIT,
    MODERN_ESP_HMAC,
    MODERN_PFS_GROUP,
    AWS_SA_LIFETIME,
    WEAK_ISAKMP_ENCRYPTION,
    WEAK_ISAKMP_HASH,
    WEAK_ISAKMP_GROUPS,
    WEAK_PFS_GROUPS,
)

# ---------------------------------------------------------------------------
# Fixtures — representative configs derived from real device output
# ---------------------------------------------------------------------------

# 2911 test config: 3DES/MD5/group2, all weak, explicit keywords
WEAK_3DES_CONFIG = """\
version 15.7
crypto isakmp policy 10
 encr 3des
 hash md5
 authentication pre-share
 group 2
 lifetime 86400
crypto isakmp key TestPSK-Tunnel1 address 192.0.2.1
crypto isakmp key TestPSK-Tunnel2 address 192.0.2.2
crypto ipsec transform-set TS-AWS-WEAK esp-3des esp-md5-hmac
 mode tunnel
ip access-list extended ACL-VPN-TUNNEL1
 permit ip 10.0.1.0 0.0.0.255 172.16.0.0 0.0.0.255
ip access-list extended ACL-VPN-TUNNEL2
 permit ip 10.0.1.0 0.0.0.255 172.16.1.0 0.0.0.255
crypto map CMAP-AWS 10 ipsec-isakmp
 set peer 192.0.2.1
 set transform-set TS-AWS-WEAK
 set pfs group2
 match address ACL-VPN-TUNNEL1
crypto map CMAP-AWS 20 ipsec-isakmp
 set peer 192.0.2.2
 set transform-set TS-AWS-WEAK
 set pfs group2
 match address ACL-VPN-TUNNEL2
"""

# Live AWS VPN connection config: IOS omits 'encr aes' and 'hash sha' (defaults)
# Actual output captured from 2911 during lab test
AWS_DEFAULT_AES_CONFIG = """\
version 15.7
crypto isakmp policy 10
 authentication pre-share
 group 2
 lifetime 28800
crypto isakmp key LabGWJ5YCTjSJtRFvqB0Hxrv address 3.211.150.159
crypto isakmp key Labhnv44RJsmhLXnZ4ZpdKro address 34.192.251.234
crypto ipsec transform-set TS-AWS-V1 esp-aes esp-sha-hmac
 mode tunnel
ip access-list extended ACL-AWS-VPN
 permit ip 10.0.1.0 0.0.0.255 10.10.1.0 0.0.0.255
crypto map CMAP-AWS 10 ipsec-isakmp
 set peer 3.211.150.159
 set transform-set TS-AWS-V1
 set pfs group2
 match address ACL-AWS-VPN
crypto map CMAP-AWS 20 ipsec-isakmp
 set peer 34.192.251.234
 set transform-set TS-AWS-V1
 set pfs group2
 match address ACL-AWS-VPN
"""

# All entries already have ikev2-profile — nothing to migrate
ALREADY_MIGRATED_CONFIG = """\
crypto isakmp policy 10
 encr aes
 authentication pre-share
 group 14
crypto isakmp key SomeKey address 1.2.3.4
crypto ipsec transform-set TS-V2 esp-aes 256 esp-sha512-hmac
 mode tunnel
crypto map CMAP 10 ipsec-isakmp
 set peer 1.2.3.4
 set transform-set TS-V2
 set pfs group21
 set ikev2-profile EXISTING-PROFILE
 match address ACL1
"""

# One entry migrated, one not — partial state
PARTIAL_MIGRATION_CONFIG = """\
crypto isakmp policy 10
 encr 3des
 hash md5
 authentication pre-share
 group 2
crypto isakmp key OldKey address 192.0.2.1
crypto isakmp key NewKey address 10.0.0.1
crypto ipsec transform-set TS-WEAK esp-3des esp-md5-hmac
 mode tunnel
crypto ipsec transform-set TS-STRONG esp-aes 256 esp-sha512-hmac
 mode tunnel
crypto map CMAP 10 ipsec-isakmp
 set peer 192.0.2.1
 set transform-set TS-WEAK
 set pfs group2
 match address ACL1
crypto map CMAP 20 ipsec-isakmp
 set peer 10.0.0.1
 set transform-set TS-STRONG
 set pfs group21
 set ikev2-profile EXISTING-PROFILE
 match address ACL2
"""

# No crypto config at all
EMPTY_CRYPTO_CONFIG = """\
version 15.7
hostname router1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
"""

# PSK with subnet mask — peer IP matches the PSK address exactly
PSK_WITH_MASK_CONFIG = """\
crypto isakmp key MyKey address 10.0.0.1 255.255.255.0
crypto ipsec transform-set TS1 esp-aes esp-sha-hmac
crypto map MAP1 10 ipsec-isakmp
 set peer 10.0.0.1
 set transform-set TS1
 set pfs group14
 match address ACL1
"""

# Multiple policies: one weak, one strong
MULTI_POLICY_CONFIG = """\
crypto isakmp policy 10
 encr 3des
 hash md5
 group 2
crypto isakmp policy 20
 encr aes 256
 hash sha256
 group 14
"""


# ---------------------------------------------------------------------------
# ConfigParser: IOS default handling
# ---------------------------------------------------------------------------

class TestConfigParserDefaults(unittest.TestCase):

    def test_explicit_3des_parsed(self):
        p = ConfigParser(WEAK_3DES_CONFIG)
        policy = p.isakmp_policies[0]
        self.assertEqual(policy.encryption, "3des")

    def test_explicit_md5_parsed(self):
        p = ConfigParser(WEAK_3DES_CONFIG)
        policy = p.isakmp_policies[0]
        self.assertEqual(policy.hash_alg, "md5")

    def test_explicit_group2_parsed(self):
        p = ConfigParser(WEAK_3DES_CONFIG)
        policy = p.isakmp_policies[0]
        self.assertEqual(policy.group, "2")

    def test_missing_encr_line_defaults_to_aes(self):
        # AWS VPN: IOS omits 'encr aes' — AES-128 is the IOS default
        p = ConfigParser(AWS_DEFAULT_AES_CONFIG)
        self.assertEqual(p.isakmp_policies[0].encryption, "aes")

    def test_missing_hash_line_defaults_to_sha(self):
        # IOS omits 'hash sha' when SHA1 is default
        p = ConfigParser(AWS_DEFAULT_AES_CONFIG)
        self.assertEqual(p.isakmp_policies[0].hash_alg, "sha")

    def test_missing_group_line_defaults_to_group2(self):
        # group2 is the IOS default and is a FN72510 target
        config = "crypto isakmp policy 10\n authentication pre-share\n"
        p = ConfigParser(config)
        self.assertEqual(p.isakmp_policies[0].group, "2")

    def test_aes256_captured_with_key_size(self):
        config = "crypto isakmp policy 10\n encr aes 256\n group 14\n"
        p = ConfigParser(config)
        self.assertEqual(p.isakmp_policies[0].encryption, "aes 256")

    def test_explicit_group14_preserved(self):
        config = "crypto isakmp policy 10\n encr aes\n group 14\n"
        p = ConfigParser(config)
        self.assertEqual(p.isakmp_policies[0].group, "14")

    def test_multiple_policies_parsed(self):
        p = ConfigParser(MULTI_POLICY_CONFIG)
        self.assertEqual(len(p.isakmp_policies), 2)
        priorities = {pol.priority for pol in p.isakmp_policies}
        self.assertEqual(priorities, {"10", "20"})

    def test_empty_config_no_crash(self):
        p = ConfigParser(EMPTY_CRYPTO_CONFIG)
        self.assertEqual(len(p.isakmp_policies), 0)
        self.assertEqual(len(p.crypto_maps), 0)
        self.assertEqual(len(p.isakmp_keys), 0)
        self.assertEqual(len(p.transform_sets), 0)


# ---------------------------------------------------------------------------
# ConfigParser: PSK, transform-set, crypto map parsing
# ---------------------------------------------------------------------------

class TestConfigParserObjects(unittest.TestCase):

    def test_psk_count(self):
        p = ConfigParser(WEAK_3DES_CONFIG)
        self.assertEqual(len(p.isakmp_keys), 2)

    def test_psk_ip_and_value(self):
        p = ConfigParser(WEAK_3DES_CONFIG)
        key_map = {k.peer_ip: k.key for k in p.isakmp_keys}
        self.assertEqual(key_map["192.0.2.1"], "TestPSK-Tunnel1")
        self.assertEqual(key_map["192.0.2.2"], "TestPSK-Tunnel2")

    def test_psk_with_subnet_mask(self):
        p = ConfigParser(PSK_WITH_MASK_CONFIG)
        self.assertEqual(len(p.isakmp_keys), 1)
        self.assertEqual(p.isakmp_keys[0].peer_mask, "255.255.255.0")

    def test_transform_set_weak_parsed(self):
        p = ConfigParser(WEAK_3DES_CONFIG)
        ts = p.transform_sets["TS-AWS-WEAK"]
        self.assertIn("esp-3des", ts.transforms)
        self.assertIn("esp-md5-hmac", ts.transforms)
        self.assertEqual(ts.mode, "tunnel")

    def test_transform_set_non_weak_parsed(self):
        p = ConfigParser(AWS_DEFAULT_AES_CONFIG)
        ts = p.transform_sets["TS-AWS-V1"]
        self.assertIn("esp-aes", ts.transforms)
        self.assertIn("esp-sha-hmac", ts.transforms)

    def test_crypto_map_two_entries(self):
        p = ConfigParser(WEAK_3DES_CONFIG)
        self.assertEqual(len(p.crypto_maps), 2)

    def test_crypto_map_entry_fields(self):
        p = ConfigParser(WEAK_3DES_CONFIG)
        entry = p.crypto_maps[("CMAP-AWS", "10")]
        self.assertEqual(entry.peer, "192.0.2.1")
        self.assertEqual(entry.transform_sets, ["TS-AWS-WEAK"])
        self.assertEqual(entry.pfs, "group2")
        self.assertEqual(entry.acl, "ACL-VPN-TUNNEL1")
        self.assertIsNone(entry.ikev2_profile)

    def test_crypto_map_ikev2_profile_detected(self):
        p = ConfigParser(ALREADY_MIGRATED_CONFIG)
        entry = p.crypto_maps[("CMAP", "10")]
        self.assertEqual(entry.ikev2_profile, "EXISTING-PROFILE")

    def test_crypto_map_group14_pfs_preserved(self):
        p = ConfigParser(PSK_WITH_MASK_CONFIG)
        entry = p.crypto_maps[("MAP1", "10")]
        self.assertEqual(entry.pfs, "group14")


# ---------------------------------------------------------------------------
# has_weak_algo() — IsakmpPolicy and TransformSet
# ---------------------------------------------------------------------------

class TestHasWeakAlgo(unittest.TestCase):

    def _policy(self, enc=None, hash_alg=None, group=None):
        return IsakmpPolicy(priority="10", encryption=enc,
                            hash_alg=hash_alg, group=group)

    # --- IsakmpPolicy ---

    def test_3des_is_weak(self):
        self.assertTrue(self._policy(enc="3des", hash_alg="sha", group="14").has_weak_algo())

    def test_des_is_weak(self):
        self.assertTrue(self._policy(enc="des", hash_alg="sha", group="14").has_weak_algo())

    def test_md5_is_weak(self):
        self.assertTrue(self._policy(enc="aes", hash_alg="md5", group="14").has_weak_algo())

    def test_group2_is_weak(self):
        self.assertTrue(self._policy(enc="aes", hash_alg="sha", group="2").has_weak_algo())

    def test_group1_is_weak(self):
        self.assertTrue(self._policy(enc="aes", hash_alg="sha", group="1").has_weak_algo())

    def test_group5_is_weak(self):
        self.assertTrue(self._policy(enc="aes", hash_alg="sha", group="5").has_weak_algo())

    def test_group24_is_weak(self):
        self.assertTrue(self._policy(enc="aes", hash_alg="sha", group="24").has_weak_algo())

    def test_default_group2_is_weak(self):
        # group=None is filled to "2" by parser defaults — must be caught
        p = ConfigParser(AWS_DEFAULT_AES_CONFIG)
        self.assertTrue(p.isakmp_policies[0].has_weak_algo())

    def test_aes_sha1_group2_weak_only_due_to_group(self):
        # AES+SHA1 are OK per FN72510; group2 is the sole weak flag
        p = self._policy(enc="aes", hash_alg="sha", group="2")
        self.assertTrue(p.has_weak_algo())

    def test_aes256_sha256_group14_not_weak(self):
        self.assertFalse(self._policy(enc="aes 256", hash_alg="sha256", group="14").has_weak_algo())

    def test_aes_sha1_group14_not_weak(self):
        self.assertFalse(self._policy(enc="aes", hash_alg="sha", group="14").has_weak_algo())

    def test_group21_not_weak(self):
        self.assertFalse(self._policy(enc="aes 256", hash_alg="sha512", group="21").has_weak_algo())

    # --- TransformSet ---

    def test_ts_esp3des_weak(self):
        self.assertTrue(TransformSet("t", ["esp-3des", "esp-sha-hmac"]).has_weak_algo())

    def test_ts_espmd5_weak(self):
        self.assertTrue(TransformSet("t", ["esp-aes", "esp-md5-hmac"]).has_weak_algo())

    def test_ts_ah_md5_weak(self):
        self.assertTrue(TransformSet("t", ["ah-md5-hmac"]).has_weak_algo())

    def test_ts_espnull_weak(self):
        self.assertTrue(TransformSet("t", ["esp-null", "esp-sha-hmac"]).has_weak_algo())

    def test_ts_aes_sha1_not_weak(self):
        self.assertFalse(TransformSet("t", ["esp-aes", "esp-sha-hmac"]).has_weak_algo())

    def test_ts_aes256_sha512_not_weak(self):
        self.assertFalse(TransformSet("t", ["esp-aes", "256", "esp-sha512-hmac"]).has_weak_algo())


# ---------------------------------------------------------------------------
# IKEv2ConfigGenerator: output correctness
# ---------------------------------------------------------------------------

class TestIKEv2ConfigGenerator(unittest.TestCase):

    def _gen(self, config_text, aws_peer=None):
        p = ConfigParser(config_text)
        return IKEv2ConfigGenerator(p, aws_peer_filter=aws_peer)

    # --- Proposal ---

    def test_proposal_present(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn("crypto ikev2 proposal AWS-IKEV2-PROPOSAL", out)

    def test_proposal_encryption(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn(f" encryption {MODERN_IKE_ENCRYPTION}", out)

    def test_proposal_integrity(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn(f" integrity {MODERN_IKE_INTEGRITY}", out)

    def test_proposal_prf(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn(f" prf {MODERN_IKE_INTEGRITY}", out)

    def test_proposal_group(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn(f" group {MODERN_IKE_DH_GROUP}", out)

    # --- Keyring ---

    def test_keyring_present(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn("crypto ikev2 keyring AWS-IKEV2-KEYRING", out)

    def test_keyring_peer_name_dotted_ip(self):
        out = self._gen(AWS_DEFAULT_AES_CONFIG).generate()
        self.assertIn("peer PEER-3-211-150-159", out)
        self.assertIn("peer PEER-34-192-251-234", out)

    def test_keyring_psk_values_in_output(self):
        out = self._gen(AWS_DEFAULT_AES_CONFIG).generate()
        self.assertIn("LabGWJ5YCTjSJtRFvqB0Hxrv", out)
        self.assertIn("Labhnv44RJsmhLXnZ4ZpdKro", out)

    def test_keyring_local_and_remote_psk(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn("pre-shared-key local", out)
        self.assertIn("pre-shared-key remote", out)

    # --- Profile ---

    def test_profile_present(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn("crypto ikev2 profile AWS-IKEV2-PROFILE", out)

    def test_profile_dpd(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn("dpd 10 3 periodic", out)

    def test_profile_lifetime(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn(f" lifetime {AWS_SA_LIFETIME}", out)

    def test_profile_psk_auth(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn("authentication remote pre-share", out)
        self.assertIn("authentication local pre-share", out)

    # --- Transform-set replacement ---

    def test_weak_ts_replaced_with_v2(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn("crypto ipsec transform-set TS-AWS-WEAK-V2", out)
        self.assertIn(f"{MODERN_ESP_ENC} {MODERN_ESP_KEY_BIT} {MODERN_ESP_HMAC}", out)

    def test_weak_ts_preserves_tunnel_mode(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        # TS-AWS-WEAK has mode tunnel — replacement should too
        lines = out.splitlines()
        v2_idx = next(i for i, l in enumerate(lines) if "TS-AWS-WEAK-V2" in l)
        nearby = "\n".join(lines[v2_idx:v2_idx+3])
        self.assertIn("mode tunnel", nearby)

    def test_non_weak_ts_not_replaced(self):
        out = self._gen(AWS_DEFAULT_AES_CONFIG).generate()
        self.assertNotIn("TS-AWS-V1-V2", out)
        self.assertIn("No weak transform-sets found", out)

    def test_non_weak_ts_name_preserved_in_map_update(self):
        out = self._gen(AWS_DEFAULT_AES_CONFIG).generate()
        self.assertIn("set transform-set TS-AWS-V1", out)

    # --- Crypto map updates ---

    def test_ikev2_profile_set_on_map_entries(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn(" set ikev2-profile AWS-IKEV2-PROFILE", out)

    def test_weak_pfs_upgraded_to_group21(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn(f" set pfs {MODERN_PFS_GROUP}", out)

    def test_strong_pfs_preserved(self):
        out = self._gen(PSK_WITH_MASK_CONFIG).generate()
        self.assertIn(" set pfs group14", out)
        self.assertNotIn(" set pfs group21", out)

    def test_no_pfs_gets_group21_added(self):
        config = """\
crypto isakmp key K address 1.2.3.4
crypto ipsec transform-set TS esp-aes esp-sha-hmac
crypto map MAP 10 ipsec-isakmp
 set peer 1.2.3.4
 set transform-set TS
 match address ACL1
"""
        out = self._gen(config).generate()
        self.assertIn(f" set pfs {MODERN_PFS_GROUP}", out)

    def test_both_map_entries_updated(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn("crypto map CMAP-AWS 10 ipsec-isakmp", out)
        self.assertIn("crypto map CMAP-AWS 20 ipsec-isakmp", out)

    # --- Fragmentation ---

    def test_fragmentation_config_included(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertIn("crypto ikev2 fragmentation", out)

    # --- Additive migration (IKEv1 must not be removed) ---

    def test_no_negation_of_ikev1_objects(self):
        out = self._gen(WEAK_3DES_CONFIG).generate()
        self.assertNotIn("no crypto isakmp", out)
        self.assertNotIn("no crypto ipsec transform-set", out)

    # --- Already-migrated entries ---

    def test_already_migrated_returns_no_targets(self):
        gen = self._gen(ALREADY_MIGRATED_CONFIG)
        self.assertEqual(len(gen._target_entries()), 0)

    def test_already_migrated_output_says_nothing_to_do(self):
        out = self._gen(ALREADY_MIGRATED_CONFIG).generate()
        self.assertIn("No crypto map entries requiring IKEv2 migration", out)

    def test_partial_migration_targets_only_unmigrated(self):
        gen = self._gen(PARTIAL_MIGRATION_CONFIG)
        targets = gen._target_entries()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].seq, "10")

    def test_partial_migration_does_not_touch_migrated_entry(self):
        out = self._gen(PARTIAL_MIGRATION_CONFIG).generate()
        # seq 20 already has ikev2-profile; must not appear in map update block
        lines = out.splitlines()
        map20_updates = [l for l in lines if "CMAP 20" in l]
        self.assertEqual(len(map20_updates), 0)

    # --- Peer filter ---

    def test_aws_peer_filter_restricts_targets(self):
        gen = self._gen(WEAK_3DES_CONFIG, aws_peer="192.0.2.1")
        targets = gen._target_entries()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].peer, "192.0.2.1")

    def test_aws_peer_filter_no_match_empty(self):
        gen = self._gen(WEAK_3DES_CONFIG, aws_peer="10.99.99.99")
        self.assertEqual(len(gen._target_entries()), 0)

    # --- Missing PSK warning ---

    def test_missing_psk_generates_warning(self):
        config = """\
crypto ipsec transform-set TS esp-aes esp-sha-hmac
crypto map MAP 10 ipsec-isakmp
 set peer 1.2.3.4
 set transform-set TS
 match address ACL1
"""
        gen = self._gen(config)
        gen.generate()
        self.assertTrue(
            any("1.2.3.4" in w or "PSK" in w for w in gen.warnings),
            f"Expected PSK warning, got: {gen.warnings}"
        )


# ---------------------------------------------------------------------------
# IKEv2JsonPayloadBuilder: YANG payload structure
# ---------------------------------------------------------------------------

class TestIKEv2JsonPayloadBuilder(unittest.TestCase):

    def _builder(self, config_text):
        return IKEv2JsonPayloadBuilder(ConfigParser(config_text))

    def test_proposal_type_empty_leaves_are_list_of_none(self):
        # YANG type empty encoded as [null] in JSON (Python: [None])
        prop = self._builder(WEAK_3DES_CONFIG).build_proposal()
        self.assertEqual(prop["encryption"]["aes-cbc-256"], [None])
        self.assertEqual(prop["integrity"]["sha512"], [None])
        self.assertEqual(prop["prf"]["sha512"], [None])

    def test_proposal_dh_group_spelled_out(self):
        prop = self._builder(WEAK_3DES_CONFIG).build_proposal()
        self.assertIn("twenty-one", prop["group"])

    def test_keyring_name(self):
        kr = self._builder(WEAK_3DES_CONFIG).build_keyring()
        self.assertEqual(kr["name"], "AWS-IKEV2-KEYRING")

    def test_keyring_peer_names_dashes(self):
        kr = self._builder(AWS_DEFAULT_AES_CONFIG).build_keyring()
        peer_names = {p["name"] for p in kr["peer"]}
        self.assertIn("PEER-3-211-150-159", peer_names)
        self.assertIn("PEER-34-192-251-234", peer_names)

    def test_keyring_peer_ip_address(self):
        kr = self._builder(AWS_DEFAULT_AES_CONFIG).build_keyring()
        peers = {p["name"]: p for p in kr["peer"]}
        self.assertEqual(
            peers["PEER-3-211-150-159"]["address"]["ipv4"]["ipv4-address"],
            "3.211.150.159"
        )

    def test_keyring_no_mask_defaults_to_host(self):
        kr = self._builder(WEAK_3DES_CONFIG).build_keyring()
        peers = {p["name"]: p for p in kr["peer"]}
        self.assertEqual(
            peers["PEER-192-0-2-1"]["address"]["ipv4"]["ipv4-mask"],
            "255.255.255.255"
        )

    def test_keyring_mask_from_psk_entry(self):
        kr = self._builder(PSK_WITH_MASK_CONFIG).build_keyring()
        # The single peer inherits mask from isakmp key
        self.assertEqual(
            kr["peer"][0]["address"]["ipv4"]["ipv4-mask"],
            "255.255.255.0"
        )

    def test_profile_dpd_settings(self):
        profile = self._builder(WEAK_3DES_CONFIG).build_profile()
        self.assertEqual(profile["dpd"]["interval"], 10)
        self.assertEqual(profile["dpd"]["retry"], 3)
        self.assertEqual(profile["dpd"]["query"], "periodic")

    def test_profile_lifetime(self):
        profile = self._builder(WEAK_3DES_CONFIG).build_profile()
        self.assertEqual(profile["lifetime"]["seconds"], AWS_SA_LIFETIME)

    def test_weak_ts_patch_list(self):
        ts_list = self._builder(WEAK_3DES_CONFIG).build_transform_sets()
        self.assertEqual(len(ts_list), 1)
        ts = ts_list[0]
        self.assertEqual(ts["tag"], "TS-AWS-WEAK-V2")
        self.assertEqual(ts["esp"], MODERN_ESP_ENC)
        self.assertEqual(ts["key-bit"], MODERN_ESP_KEY_BIT)
        self.assertEqual(ts["esp-hmac"], MODERN_ESP_HMAC)

    def test_non_weak_ts_returns_empty_list(self):
        self.assertEqual(self._builder(AWS_DEFAULT_AES_CONFIG).build_transform_sets(), [])

    def test_full_patch_payload_top_level_keys(self):
        payload = self._builder(WEAK_3DES_CONFIG).build_ikev2_patch_payload()
        ikev2 = payload["Cisco-IOS-XE-crypto:ikev2"]
        for key in ("proposal", "policy", "keyring", "profile"):
            self.assertIn(key, ikev2, f"Missing key: {key}")

    def test_ipsec_transform_patch_payload_none_when_no_weak(self):
        self.assertIsNone(
            self._builder(AWS_DEFAULT_AES_CONFIG).build_ipsec_transform_patch_payload()
        )

    def test_ipsec_transform_patch_payload_present_when_weak(self):
        payload = self._builder(WEAK_3DES_CONFIG).build_ipsec_transform_patch_payload()
        self.assertIsNotNone(payload)
        self.assertIn("Cisco-IOS-XE-crypto:ipsec", payload)

    def test_crypto_map_patches_count(self):
        b = self._builder(WEAK_3DES_CONFIG)
        patches = b.build_crypto_map_patches()
        self.assertEqual(len(patches), 2)

    def test_crypto_map_patch_contains_ikev2_profile(self):
        b = self._builder(WEAK_3DES_CONFIG)
        for path, payload in b.build_crypto_map_patches():
            set_obj = payload.get("Cisco-IOS-XE-crypto:set", {})
            self.assertEqual(set_obj.get("ikev2-profile"), "AWS-IKEV2-PROFILE")

    def test_crypto_map_patch_upgrades_weak_pfs(self):
        b = self._builder(WEAK_3DES_CONFIG)
        for path, payload in b.build_crypto_map_patches():
            set_obj = payload["Cisco-IOS-XE-crypto:set"]
            self.assertEqual(set_obj["pfs"]["group"], MODERN_PFS_GROUP)


# ---------------------------------------------------------------------------
# validation_report(): audit output content
# ---------------------------------------------------------------------------

class TestValidationReport(unittest.TestCase):

    def _report(self, config_text):
        p = ConfigParser(config_text)
        gen = IKEv2ConfigGenerator(p)
        return validation_report(p, gen._target_entries())

    def test_weak_enc_flagged(self):
        self.assertIn("WEAK-ENC:3des", self._report(WEAK_3DES_CONFIG))

    def test_weak_hash_flagged(self):
        self.assertIn("WEAK-HASH:md5", self._report(WEAK_3DES_CONFIG))

    def test_weak_group_flagged(self):
        self.assertIn("WEAK-GROUP:2", self._report(WEAK_3DES_CONFIG))

    def test_default_aes_no_enc_flag(self):
        # AES-128 (default) is not a weak encryption algorithm
        report = self._report(AWS_DEFAULT_AES_CONFIG)
        self.assertNotIn("WEAK-ENC", report)

    def test_default_sha_no_hash_flag(self):
        # SHA1 is not in WEAK_ISAKMP_HASH — only MD5 is
        report = self._report(AWS_DEFAULT_AES_CONFIG)
        self.assertNotIn("WEAK-HASH", report)

    def test_default_group2_is_flagged(self):
        # group2 is the default and is weak — must appear even without explicit group line
        report = self._report(AWS_DEFAULT_AES_CONFIG)
        self.assertIn("WEAK-GROUP:2", report)

    def test_strong_policy_shows_ok(self):
        config = """\
crypto isakmp policy 10
 encr aes 256
 hash sha256
 authentication pre-share
 group 14
"""
        self.assertIn("algorithms OK for 17.11+", self._report(config))

    def test_weak_transform_set_flagged(self):
        self.assertIn("*** WEAK", self._report(WEAK_3DES_CONFIG))

    def test_target_count_correct(self):
        self.assertIn("Crypto map entries targeted for migration: 2",
                      self._report(WEAK_3DES_CONFIG))

    def test_zero_targets_when_all_migrated(self):
        self.assertIn("targeted for migration: 0",
                      self._report(ALREADY_MIGRATED_CONFIG))

    def test_psk_peer_ips_listed(self):
        report = self._report(WEAK_3DES_CONFIG)
        self.assertIn("192.0.2.1", report)
        self.assertIn("192.0.2.2", report)


# ---------------------------------------------------------------------------
# End-to-end: parse a config, generate, verify critical commands present
# ---------------------------------------------------------------------------

class TestEndToEnd(unittest.TestCase):

    def _output(self, config_text, aws_peer=None):
        p = ConfigParser(config_text)
        gen = IKEv2ConfigGenerator(p, aws_peer_filter=aws_peer)
        return gen.generate()

    def test_3des_full_config_all_required_sections(self):
        out = self._output(WEAK_3DES_CONFIG)
        for expected in [
            "crypto ikev2 proposal AWS-IKEV2-PROPOSAL",
            "crypto ikev2 policy AWS-IKEV2-POLICY",
            "crypto ikev2 keyring AWS-IKEV2-KEYRING",
            "crypto ikev2 profile AWS-IKEV2-PROFILE",
            "TS-AWS-WEAK-V2",
            "set ikev2-profile AWS-IKEV2-PROFILE",
            "set pfs group21",
            "dpd 10 3 periodic",
            "crypto ikev2 fragmentation",
        ]:
            self.assertIn(expected, out, f"Missing: {expected!r}")

    def test_aws_default_aes_pfs_only_upgrade(self):
        # TS not weak → no -V2 replacement; only PFS and profile change
        out = self._output(AWS_DEFAULT_AES_CONFIG)
        self.assertNotIn("TS-AWS-V1-V2", out)
        self.assertIn("set transform-set TS-AWS-V1", out)
        self.assertIn("set pfs group21", out)
        self.assertIn("set ikev2-profile AWS-IKEV2-PROFILE", out)

    def test_partial_migration_only_seq10_in_output(self):
        out = self._output(PARTIAL_MIGRATION_CONFIG)
        self.assertIn("crypto map CMAP 10 ipsec-isakmp", out)
        # seq 20 already migrated — must not appear
        for line in out.splitlines():
            self.assertNotIn("CMAP 20", line)

    def test_peer_filter_single_entry(self):
        out = self._output(WEAK_3DES_CONFIG, aws_peer="192.0.2.1")
        # Only PEER-192-0-2-1 in keyring
        self.assertIn("PEER-192-0-2-1", out)
        self.assertNotIn("PEER-192-0-2-2", out)

    def test_ikev1_config_untouched(self):
        out = self._output(WEAK_3DES_CONFIG)
        self.assertNotIn("no crypto isakmp", out)
        self.assertNotIn("no crypto ipsec transform-set", out)
        self.assertNotIn("no crypto map", out)


# Route-based AWS VPN with VTI + BGP.  This is the production shape that the
# original crypto-map-only tool missed.
VTI_BGP_CONFIG = """\
version 15.7
crypto isakmp policy 10
 encr 3des
 hash md5
 authentication pre-share
 group 2
 lifetime 28800
crypto isakmp key VtiPsk1 address 192.0.2.1
crypto ipsec transform-set AWS-VTI-TS esp-3des esp-md5-hmac
 mode tunnel
crypto ipsec profile AWS-VTI-PROFILE
 set transform-set AWS-VTI-TS
 set pfs group2
interface Tunnel1
 ip address 169.254.10.2 255.255.255.252
 tunnel source GigabitEthernet0/0
 tunnel mode ipsec ipv4
 tunnel destination 192.0.2.1
 tunnel protection ipsec profile AWS-VTI-PROFILE
router bgp 65000
 neighbor 169.254.10.1 remote-as 7224
 neighbor 169.254.10.1 timers 10 30 30
 address-family ipv4
  neighbor 169.254.10.1 activate
"""


class TestVtiBgpSupport(unittest.TestCase):

    def test_vti_objects_parsed(self):
        p = ConfigParser(VTI_BGP_CONFIG)
        self.assertIn("AWS-VTI-PROFILE", p.ipsec_profiles)
        self.assertIn("Tunnel1", p.tunnel_interfaces)
        self.assertEqual(p.tunnel_interfaces["Tunnel1"].destination, "192.0.2.1")
        self.assertEqual(p.tunnel_interfaces["Tunnel1"].protection_profile, "AWS-VTI-PROFILE")
        self.assertIn("169.254.10.1", p.bgp_neighbors)

    def test_vti_profile_gets_ikev2_binding_and_bgp_note(self):
        p = ConfigParser(VTI_BGP_CONFIG)
        out = IKEv2ConfigGenerator(p).generate()
        self.assertIn("crypto ipsec transform-set AWS-VTI-TS-V2", out)
        self.assertIn("crypto ipsec profile AWS-VTI-PROFILE", out)
        self.assertIn("set transform-set AWS-VTI-TS-V2", out)
        self.assertIn("set pfs group21", out)
        self.assertIn("set ikev2-profile AWS-IKEV2-PROFILE", out)
        self.assertIn("BGP config is intentionally not changed", out)
        self.assertIn("169.254.10.1 remote-as 7224", out)
        self.assertNotIn("crypto map", out)

    def test_vti_peer_filter(self):
        p = ConfigParser(VTI_BGP_CONFIG)
        out = IKEv2ConfigGenerator(p, aws_peer_filter="203.0.113.1").generate()
        self.assertIn("No crypto map entries requiring IKEv2 migration", out)
        out = IKEv2ConfigGenerator(p, aws_peer_filter="192.0.2.1").generate()
        self.assertIn("crypto ipsec profile AWS-VTI-PROFILE", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
