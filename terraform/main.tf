terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  # Compute wildcard masks for Cisco ACL output (255 - each octet of the subnet mask)
  subnet_network  = cidrhost(var.subnet_cidr, 0)
  onprem_network  = cidrhost(var.onprem_cidr, 0)
  subnet_wildcard = join(".", [for o in split(".", cidrnetmask(var.subnet_cidr)) : tostring(255 - tonumber(o))])
  onprem_wildcard = join(".", [for o in split(".", cidrnetmask(var.onprem_cidr)) : tostring(255 - tonumber(o))])
}

# ── VPC ───────────────────────────────────────────────────────────────────────

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  tags = { Name = "ikev2-lab-vpc" }
}

resource "aws_subnet" "lab" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = var.subnet_cidr
  availability_zone = "${var.aws_region}a"
  tags = { Name = "ikev2-lab-subnet" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "ikev2-lab-igw" }
}

resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "ikev2-lab-rt" }
}

resource "aws_route_table_association" "lab" {
  subnet_id      = aws_subnet.lab.id
  route_table_id = aws_route_table.lab.id
}

# Route back to on-prem through the VGW (static — no BGP)
resource "aws_route" "onprem" {
  route_table_id         = aws_route_table.lab.id
  destination_cidr_block = var.onprem_cidr
  gateway_id             = aws_vpn_gateway.lab.id
  depends_on             = [aws_route_table.lab]
}

# ── Security Group ────────────────────────────────────────────────────────────

resource "aws_security_group" "lab" {
  name        = "ikev2-lab-sg"
  description = "ICMP from on-prem LAN and VPC for tunnel testing"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "ICMP from on-prem LAN"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.onprem_cidr]
  }

  ingress {
    description = "ICMP within VPC"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ikev2-lab-sg" }
}

# ── EC2 Target ────────────────────────────────────────────────────────────────

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "target" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.nano"
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.lab.id]

  # No key pair — access via VPN only; ping is the test
  tags = { Name = "ikev2-lab-target" }
}

# ── VPN ───────────────────────────────────────────────────────────────────────

resource "aws_customer_gateway" "lab" {
  bgp_asn    = 65000
  ip_address = var.router_public_ip
  type       = "ipsec.1"
  tags       = { Name = "ikev2-lab-cgw" }
}

resource "aws_vpn_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "ikev2-lab-vgw" }
}

# Enable route propagation so the VGW automatically advertises on-prem routes
resource "aws_vpn_gateway_route_propagation" "lab" {
  vpn_gateway_id = aws_vpn_gateway.lab.id
  route_table_id = aws_route_table.lab.id
}

resource "aws_vpn_connection" "lab" {
  vpn_gateway_id      = aws_vpn_gateway.lab.id
  customer_gateway_id = aws_customer_gateway.lab.id
  type                = "ipsec.1"
  static_routes_only  = true

  tunnel1_preshared_key = var.tunnel1_psk
  tunnel2_preshared_key = var.tunnel2_psk

  # IKEv2 only — no IKEv1 fallback
  tunnel1_ike_versions = ["ikev2"]
  tunnel2_ike_versions = ["ikev2"]

  # Phase 1 — match MODERN_IKE_* constants in ikev1_to_ikev2_migrate.py
  tunnel1_phase1_encryption_algorithms = ["AES256"]
  tunnel2_phase1_encryption_algorithms = ["AES256"]
  tunnel1_phase1_integrity_algorithms  = ["SHA2-512"]
  tunnel2_phase1_integrity_algorithms  = ["SHA2-512"]
  tunnel1_phase1_dh_group_numbers      = [21]
  tunnel2_phase1_dh_group_numbers      = [21]
  tunnel1_phase1_lifetime_seconds      = 86400
  tunnel2_phase1_lifetime_seconds      = 86400

  # Phase 2 — match MODERN_ESP_* constants in ikev1_to_ikev2_migrate.py
  tunnel1_phase2_encryption_algorithms = ["AES256"]
  tunnel2_phase2_encryption_algorithms = ["AES256"]
  tunnel1_phase2_integrity_algorithms  = ["SHA2-512"]
  tunnel2_phase2_integrity_algorithms  = ["SHA2-512"]
  tunnel1_phase2_dh_group_numbers      = [21]
  tunnel2_phase2_dh_group_numbers      = [21]
  tunnel1_phase2_lifetime_seconds      = 28800
  tunnel2_phase2_lifetime_seconds      = 28800

  tunnel1_dpd_timeout_action = "restart"
  tunnel2_dpd_timeout_action = "restart"

  tags = { Name = "ikev2-lab-vpn" }
}

resource "aws_vpn_connection_route" "onprem" {
  vpn_connection_id      = aws_vpn_connection.lab.id
  destination_cidr_block = var.onprem_cidr
}
