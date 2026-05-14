output "vpc_id" {
  value = aws_vpc.lab.id
}

output "vpn_connection_id" {
  value = aws_vpn_connection.lab.id
}

output "tunnel1_outside_ip" {
  value = aws_vpn_connection.lab.tunnel1_address
}

output "tunnel2_outside_ip" {
  value = aws_vpn_connection.lab.tunnel2_address
}

output "ec2_private_ip" {
  description = "Ping target — use this in your ping test"
  value       = aws_instance.target.private_ip
}

# Ready-to-paste IKEv2 router config generated from Terraform outputs.
# PSKs are marked sensitive so they only appear in `tofu output -json router_config`.
output "router_config" {
  description = "IKEv2 config to paste onto the Cisco router"
  sensitive   = true
  value       = <<-EOT
    ! ── IKEv2 Proposal / Policy ─────────────────────────────────────────────
    crypto ikev2 proposal IKEV2-PROP-AWS
     encryption aes-cbc-256
     integrity  sha512
     prf        sha512
     group      21
    !
    crypto ikev2 policy IKEV2-POL-AWS
     proposal IKEV2-PROP-AWS
    !
    ! ── Keyring ──────────────────────────────────────────────────────────────
    crypto ikev2 keyring IKEV2-KR-AWS
     peer AWS-T1
      address ${aws_vpn_connection.lab.tunnel1_address}
      pre-shared-key ${var.tunnel1_psk}
     !
     peer AWS-T2
      address ${aws_vpn_connection.lab.tunnel2_address}
      pre-shared-key ${var.tunnel2_psk}
    !
    ! ── IKEv2 Profiles ───────────────────────────────────────────────────────
    crypto ikev2 profile IKEV2-PROF-T1
     match identity remote address ${aws_vpn_connection.lab.tunnel1_address} 255.255.255.255
     authentication remote pre-share
     authentication local  pre-share
     keyring local IKEV2-KR-AWS
     dpd 30 5 periodic
    !
    crypto ikev2 profile IKEV2-PROF-T2
     match identity remote address ${aws_vpn_connection.lab.tunnel2_address} 255.255.255.255
     authentication remote pre-share
     authentication local  pre-share
     keyring local IKEV2-KR-AWS
     dpd 30 5 periodic
    !
    ! ── Transform Set ────────────────────────────────────────────────────────
    crypto ipsec transform-set TS-AWS-IKEV2 esp-aes 256 esp-sha512-hmac
     mode tunnel
    !
    ! ── Crypto Map ───────────────────────────────────────────────────────────
    crypto map CMAP 10 ipsec-isakmp
     set peer ${aws_vpn_connection.lab.tunnel1_address}
     set transform-set TS-AWS-IKEV2
     set ikev2-profile IKEV2-PROF-T1
     set security-association lifetime seconds 28800
     set pfs group21
     match address VPN-TRAFFIC
    !
    crypto map CMAP 20 ipsec-isakmp
     set peer ${aws_vpn_connection.lab.tunnel2_address}
     set transform-set TS-AWS-IKEV2
     set ikev2-profile IKEV2-PROF-T2
     set security-association lifetime seconds 28800
     set pfs group21
     match address VPN-TRAFFIC
    !
    ! ── ACL ──────────────────────────────────────────────────────────────────
    ip access-list extended VPN-TRAFFIC
     permit ip ${local.onprem_network} ${local.onprem_wildcard} ${local.subnet_network} ${local.subnet_wildcard}
    !
    ! ── Apply to WAN interface (edit interface name as needed) ───────────────
    ! interface GigabitEthernet0/0
    !  crypto map CMAP
    !
    ! ── Verify ───────────────────────────────────────────────────────────────
    ! show crypto ikev2 sa
    ! show crypto ipsec sa
    ! ping ${aws_instance.target.private_ip} source <LAN-IP> repeat 10
  EOT
}
