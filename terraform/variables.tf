variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "router_public_ip" {
  description = "Current public IP of the on-premises Cisco router (check mindfury.duckdns.org)"
  type        = string
}

variable "onprem_cidr" {
  description = "On-premises LAN CIDR that needs to reach the VPC"
  type        = string
  default     = "10.0.1.0/24"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.10.0.0/16"
}

variable "subnet_cidr" {
  description = "Subnet CIDR for EC2 target instances"
  type        = string
  default     = "10.10.1.0/24"
}

variable "tunnel1_psk" {
  description = "Pre-shared key for VPN tunnel 1 (8-64 chars, alphanumeric + _ + . only, no leading zero)"
  type        = string
  sensitive   = true
}

variable "tunnel2_psk" {
  description = "Pre-shared key for VPN tunnel 2 (must differ from tunnel1_psk)"
  type        = string
  sensitive   = true
}
