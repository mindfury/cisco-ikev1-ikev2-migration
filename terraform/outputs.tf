output "vpc_id" {
  value = aws_vpc.lab.id
}

output "vpn_connection_id" {
  value = aws_vpn_connection.lab.id
}

# ── Tunnel outside IPs (IKE endpoints on the AWS VGW side) ───────────────────
output "tunnel1_outside_ip" {
  value = local.t1_outside_ip
}

output "tunnel2_outside_ip" {
  value = local.t2_outside_ip
}

# ── Tunnel inside IPs (BGP peering addresses) ─────────────────────────────────
# These are the 169.254.x.x/30 link-local addresses AWS assigns to each tunnel.
# The CGW inside IP goes on the router tunnel interface.
# The VGW inside IP is the BGP neighbor address on the router.

output "tunnel1_cgw_inside_ip" {
  description = "Router-side inside IP for Tunnel1 — use as 'ip address' on the tunnel interface"
  value       = local.t1_cgw_ip
}

output "tunnel1_vgw_inside_ip" {
  description = "AWS-side inside IP for Tunnel1 — use as 'neighbor' in router BGP config"
  value       = local.t1_vgw_ip
}

output "tunnel2_cgw_inside_ip" {
  description = "Router-side inside IP for Tunnel2"
  value       = local.t2_cgw_ip
}

output "tunnel2_vgw_inside_ip" {
  description = "AWS-side inside IP for Tunnel2 — use as 'neighbor' in router BGP config"
  value       = local.t2_vgw_ip
}

output "aws_bgp_asn" {
  description = "AWS VGW BGP ASN — use as 'remote-as' in router BGP config"
  value       = local.aws_bgp_asn
}

output "ec2_private_ip" {
  description = "Ping target inside the VPC"
  value       = aws_instance.target.private_ip
}

# ── Pre-migration router config (IKEv1 VTI + BGP) ────────────────────────────
# Paste this onto the router BEFORE running the migration tool.
# It deliberately uses weak IKEv1 crypto (group2 PFS) so the migration tool
# has something real to flag and fix.
output "router_config" {
  description = "IKEv1 VTI + BGP config to apply to the router before running the migration tool"
  sensitive   = true
  value       = <<-EOT
    ! ══════════════════════════════════════════════════════════════════════════
    ! PRE-MIGRATION CONFIG — IKEv1 VTI + BGP
    ! Apply this to the router, verify BGP adjacency and ping, THEN run the
    ! migration tool to generate the IKEv2 additions.
    ! ══════════════════════════════════════════════════════════════════════════
    !
    ! ── IKEv1 Phase 1 ─────────────────────────────────────────────────────────
    ! group 2 is deliberately weak — FN72510 target, will be flagged by audit
    crypto isakmp policy 10
     encr aes 256
     hash sha256
     authentication pre-share
     group 14
     lifetime 28800
    !
    crypto isakmp key ${var.tunnel1_psk} address ${local.t1_outside_ip}
    crypto isakmp key ${var.tunnel2_psk} address ${local.t2_outside_ip}
    !
    ! ── Phase 2 transform-set ─────────────────────────────────────────────────
    crypto ipsec transform-set TS-AWS-VTI esp-aes 256 esp-sha256-hmac
     mode tunnel
    !
    ! ── IPsec profile — NO ikev2-profile (pre-migration state) ───────────────
    ! pfs group2 is deliberately weak — will be upgraded to group21 by tool
    crypto ipsec profile AWS-VTI-PROFILE
     set transform-set TS-AWS-VTI
     set pfs group2
    !
    ! ── Tunnel interfaces ─────────────────────────────────────────────────────
    interface Tunnel1
     ip address ${local.t1_cgw_ip} 255.255.255.252
     tunnel source GigabitEthernet0/0
     tunnel mode ipsec ipv4
     tunnel destination ${local.t1_outside_ip}
     tunnel protection ipsec profile AWS-VTI-PROFILE
    !
    interface Tunnel2
     ip address ${local.t2_cgw_ip} 255.255.255.252
     tunnel source GigabitEthernet0/0
     tunnel mode ipsec ipv4
     tunnel destination ${local.t2_outside_ip}
     tunnel protection ipsec profile AWS-VTI-PROFILE
    !
    ! ── BGP ───────────────────────────────────────────────────────────────────
    router bgp ${var.router_bgp_asn}
     bgp log-neighbor-changes
     neighbor ${local.t1_vgw_ip} remote-as ${local.aws_bgp_asn}
     neighbor ${local.t1_vgw_ip} timers 10 30 30
     neighbor ${local.t2_vgw_ip} remote-as ${local.aws_bgp_asn}
     neighbor ${local.t2_vgw_ip} timers 10 30 30
     !
     address-family ipv4
      network ${local.onprem_network} mask ${cidrnetmask(var.onprem_cidr)}
      neighbor ${local.t1_vgw_ip} activate
      neighbor ${local.t1_vgw_ip} soft-reconfiguration inbound
      neighbor ${local.t2_vgw_ip} activate
      neighbor ${local.t2_vgw_ip} soft-reconfiguration inbound
     exit-address-family
    !
    ! ── Verify IKEv1 is up before running migration tool ─────────────────────
    ! show crypto isakmp sa          → expect QM_IDLE for both peers
    ! show crypto ipsec sa           → expect encaps/decaps incrementing
    ! show ip bgp summary            → expect neighbor state = Established
    ! show ip route bgp              → expect ${local.subnet_network}/${replace(var.subnet_cidr, "/.*\\//", "")} via BGP
    ! ping ${aws_instance.target.private_ip} source ${local.onprem_network} repeat 10
  EOT
}

# ── Post-migration reference (what the tool will generate) ───────────────────
# Run: python3 ikev1_to_ikev2_migrate.py --config-file <captured-run>.cfg
# The tool output will look approximately like this.
output "router_config_ikev2_preview" {
  description = "IKEv2 additions the migration tool will generate (for reference)"
  sensitive   = true
  value       = <<-EOT
    ! ── IKEv2 additions (generated by migration tool — do not paste manually) ─
    ! Run the tool against the captured running-config to get the exact output.
    !
    ! crypto ikev2 proposal AWS-IKEV2-PROPOSAL
    !  encryption aes-cbc-256
    !  integrity  sha512
    !  prf        sha512
    !  group      21
    !
    ! crypto ikev2 keyring AWS-IKEV2-KEYRING
    !  peer PEER-${local.t1_outside_ip}
    !   address ${local.t1_outside_ip}
    !   pre-shared-key <PSK from isakmp key line>
    !  peer PEER-${local.t2_outside_ip}
    !   address ${local.t2_outside_ip}
    !   pre-shared-key <PSK from isakmp key line>
    !
    ! crypto ikev2 profile AWS-IKEV2-PROFILE
    !  match identity remote address 0.0.0.0
    !  authentication remote pre-share
    !  authentication local  pre-share
    !  keyring local AWS-IKEV2-KEYRING
    !  dpd 10 3 periodic
    !
    ! crypto ipsec profile AWS-VTI-PROFILE  ← EXISTING profile, updated in-place
    !  set transform-set TS-AWS-VTI         ← kept (already AES-256)
    !  set pfs group21                      ← upgraded from group2
    !  set ikev2-profile AWS-IKEV2-PROFILE  ← THE activation switch
    !
    ! Rollback: remove 'set ikev2-profile' from the ipsec profile
  EOT
}
