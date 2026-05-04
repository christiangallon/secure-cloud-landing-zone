# =============================================================================
# NETWORK MODULE - VPC Infrastructure
# =============================================================================
# This module creates a secure VPC with public and private subnets.
#
# SECURITY ARCHITECTURE:
# =====================
# Internet ----> Internet Gateway ----> Public Subnet (ALB only)
#                                              |
#                                              v
# Private Subnet (EC2/App) <---- NAT Gateway <---- Private Subnet (RDS)
#                                          ^
#                                          |
#                                   (Outbound only)
#
# Why this design?
# 1. PUBLIC SUBNETS: Only load balancers here. They face the internet so
#    users can access your application. They're monitored closely.
#
# 2. PRIVATE SUBNETS: Application servers here. No direct internet access.
#    If compromised, attackers can't receive inbound connections.
#
# 3. NAT GATEWAY: Private instances CAN make outbound connections (updates,
#    API calls) but NOBODY can connect IN directly.
#
# 4. RDS IN PRIVATE SUBNETS: Database is completely hidden. Only app servers
#    in the same VPC can reach it.

# =============================================================================
# RESOURCE: VPC
# =============================================================================
# The VPC is the isolated network container for all our resources.
# Security Features:
# - DNS hostnames enabled: EC2 instances get DNS names
# - DNS resolution enabled: Instances can resolve AWS service DNS

resource "aws_vpc" "main" {
  # CIDR block defines the IP range
  # /16 gives us 65,536 IPs - plenty for most workloads
  cidr_block = var.vpc_cidr

  # Enable DNS features for better AWS integration
  enable_dns_hostnames = true  # EC2 instances get DNS hostnames
  enable_dns_support   = true # DNS resolution within VPC

  # Instance tenancy ensures dedicated hardware for compliance
  # Options: "default" | "dedicated" | "host"
  # "dedicated" is required for some compliance frameworks
  instance_tenancy = "default"

  tags = {
    Name        = "${var.environment}-vpc"
    Description = "Secure Cloud Landing Zone VPC"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# RESOURCE: INTERNET GATEWAY
# =============================================================================
# The Internet Gateway allows communication between the VPC and the internet.
# Security: This is attached to the VPC, not directly to instances.
# The IGW is highly available by design (AWS manages it).
# Without an IGW, the VPC is completely isolated from the internet.

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.environment}-igw"
    Description = "Internet Gateway for public subnet access"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# RESOURCE: ELASTIC IP (for NAT Gateway)
# =============================================================================
# An Elastic IP is a static, AWS-owned public IP address.
# Why we need it: NAT Gateway needs a fixed IP to be reachable from internet.
# The EIP is associated with the NAT Gateway, not directly with instances.
# Cost: EIPs are free when associated with a NAT Gateway in use.

resource "aws_eip" "nat" {
  # NAT Gateway must be in a public subnet (has route to IGW)
  domain = "vpc"

  # Lifecycle setting prevents recreation during updates
  # If the EIP already exists, don't recreate it
  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "${var.environment}-nat-eip"
    Description = "Elastic IP for NAT Gateway"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# RESOURCE: NAT GATEWAY
# =============================================================================
# NAT Gateway enables private subnet instances to access the internet
# while preventing inbound connections from the internet.
#
# HOW IT WORKS:
# 1. Private instance wants to update packages -> makes request
# 2. Request goes through private subnet's route table
# 3. Route table sends traffic to NAT Gateway in public subnet
# 4. NAT Gateway has EIP -> can communicate with internet
# 5. Response comes back to NAT Gateway -> forwarded to private instance
#
# SECURITY BENEFIT:
# - Private instances get outbound internet (for updates, APIs)
# - But NOBODY can initiate a connection TO private instances
# - Attackers can't directly attack your app servers
#
# COST: ~$30/month + data processing fees. Use in prod or if instances
# need internet access. For完全 isolated, use Private Subnets only.

resource "aws_nat_gateway" "main" {
  # NAT Gateway must be in a public subnet (needs IGW route)
  subnet_id = aws_subnet.public[0].id

  # The Elastic IP is associated with the NAT Gateway
  allocation_id = aws_eip.nat.id

  # Dependency: NAT Gateway needs IGW to exist
  # Terraform figures this out, but being explicit helps
  depends_on = [aws_internet_gateway.main]

  tags = {
    Name        = "${var.environment}-nat"
    Description = "NAT Gateway for private subnet outbound access"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# RESOURCE: PUBLIC SUBNETS
# =============================================================================
# Public subnets are directly reachable from the internet.
# WHAT GOES HERE: Load Balancers, NAT Gateways, Bastion Hosts
# WHAT DOESN'T: Application servers, databases
#
# Security: Instances in public subnets SHOULD be hardened because
# they're directly exposed. In our design, only the ALB goes here.
#
# AZ REDUNDANCY: We create subnets in multiple AZs for high availability.
# If one AZ fails, the other continues serving traffic.

resource "aws_subnet" "public" {
  # Create one subnet per availability zone
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]

  # Map public IP on launch: EC2 instances get public IPs by default
  # We DON'T enable this because only the ALB should be in public subnets
  # and ALB doesn't need instance-level public IPs (routes through DNS)
  map_public_ip_on_launch = false

  # Enable IPv6 if needed (optional)
  # assign_ipv6_address_on_creation = false

  tags = {
    Name        = "${var.environment}-public-subnet-${var.availability_zones[count.index]}"
    Description = "Public subnet for load balancers"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    SubnetType  = "Public"

    # Tags for Auto Scaling Group to discover subnets
    "aws:cloudformation:logical-id" = "PublicSubnet${count.index + 1}"
  }
}

# =============================================================================
# RESOURCE: PRIVATE SUBNETS
# =============================================================================
# Private subnets have NO direct route to/from the internet.
# This is where your application servers and databases live.
#
# SECURITY BENEFITS:
# 1. No direct internet access -> attackers can't reach these servers
# 2. Reduced attack surface -> fewer security groups to manage
# 3. Network-level isolation -> defense in depth
#
# WHAT GOES HERE:
# - Application servers (EC2, ECS, EKS)
# - Databases (RDS, ElastiCache)
# - Internal services (Elasticsearch, Kafka)
#
# WHY TWO AZs?
# RDS Multi-AZ requires subnets in multiple AZs. This provides
# automatic failover - if one AZ fails, RDS fails over to the other.

resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  # No public IP assignment - these are truly private
  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.environment}-private-subnet-${var.availability_zones[count.index]}"
    Description = "Private subnet for application workloads"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    SubnetType  = "Private"

    "aws:cloudformation:logical-id" = "PrivateSubnet${count.index + 1}"
  }
}

# =============================================================================
# RESOURCE: PRIVATE SUBNET FOR RDS (Database)
# =============================================================================
# RDS requires subnets in multiple AZs for Multi-AZ deployment.
# We'll use the same private subnets for RDS, but this demonstrates
# how you could separate database tiers into dedicated subnets.

resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-rds-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  # Tags for cost tracking and resource management
  tags = {
    Name        = "${var.environment}-rds-subnet-group"
    Description = "RDS subnet group for Multi-AZ deployment"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# RESOURCE: ROUTE TABLE - PUBLIC
# =============================================================================
# Route tables control where network traffic goes.
# Public route table sends traffic to the Internet Gateway.
#
# DEFAULT ROUTE: Traffic to 0.0.0.0/0 (everything else) goes to IGW
# This allows public subnet instances to send/receive internet traffic.

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  # Default route: anywhere -> Internet Gateway
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
    # Can also use: carrier_gateway_id, egress_only_gateway_id, nat_gateway_id, etc.
  }

  # AWS recommends adding local route explicitly for clarity
  # It's added automatically, but being explicit documents intent

  tags = {
    Name        = "${var.environment}-public-rt"
    Description = "Route table for public subnets"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# RESOURCE: ROUTE TABLE - PRIVATE
# =============================================================================
# Private route table sends traffic through NAT Gateway.
#
# HOW TRAFFIC FLOWS:
# Private instance -> NAT Gateway -> Public subnet -> IGW -> Internet
#
# This is one-way. The NAT Gateway allows OUTBOUND connections,
# but external hosts can only RESPOND to the private instance,
# not initiate a connection to it.
#
# SECURITY: If you DON'T need outbound internet, remove the NAT route.
# Your instances will be completely isolated (more secure).

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  # Default route via NAT Gateway
  # Traffic to 0.0.0.0/0 goes to NAT Gateway (for internet access)
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  # Optional: Route to on-premises over VPN/Direct Connect
  # route {
  #   cidr_block                = "10.0.0.0/8"  # On-premises network
  #   transit_gateway_id        = "tgw-xxxxx"
  # }

  tags = {
    Name        = "${var.environment}-private-rt"
    Description = "Route table for private subnets (via NAT)"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# RESOURCE: ROUTE TABLE ASSOCIATIONS - PUBLIC
# =============================================================================
# Associate public subnets with the public route table.
# Each subnet can only have ONE route table (implicit).

resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# =============================================================================
# RESOURCE: ROUTE TABLE ASSOCIATIONS - PRIVATE
# =============================================================================

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# =============================================================================
# RESOURCE: VPC ENDPOINT - S3 (Gateway)
# =============================================================================
# VPC Endpoints allow private access to AWS services without internet.
# Gateway endpoints: S3, DynamoDB (free)
# Interface endpoints: Other services (~$0.01/hour)
#
# WHY USE S3 ENDPOINT?
# 1. Private instances can access S3 without NAT Gateway
# 2. Traffic stays within AWS network (more secure)
# 3. No internet egress fees for S3 traffic
# 4. Bucket policies can restrict to specific VPC endpoints
#
# SECURITY: With endpoint policy, we can ensure instances can ONLY
# access specific S3 buckets from within this VPC.

resource "aws_vpc_endpoint" "s3" {
  vpc_id           = aws_vpc.main.id
  service_name     = "com.amazonaws.${var.availability_zones[0].rstrip("0123456789")}.s3"  # e.g., us-east-1.s3
  # Route table IDs to associate with this endpoint
  # Traffic to S3 from these subnets will use the endpoint
  route_table_ids = aws_route_table.private[*].id

  # VPC Endpoint type: "Gateway" or "Interface"
  # Gateway: S3, DynamoDB (free, uses route table entries)
  # Interface: Other services (paid, uses ENIs)
  vpc_endpoint_type = "Gateway"

  # Policy: Restrict S3 access to specific buckets
  # Security: Ensures even if credentials are leaked, S3 access is limited
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "LimitS3AccessToVPC"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          "arn:aws:s3:::*",
          "arn:aws:s3:::*/*"
        ]
        Condition = {
          # Block access if NOT coming from our VPC endpoint
          # This prevents access even with valid credentials
          # unless they're from within the VPC
          Bool = {
            "aws:ViaWSService" = "false"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-s3-endpoint"
    Description = "S3 Gateway VPC Endpoint"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "VPC CIDR block"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_ip" {
  description = "Elastic IP address of NAT Gateway"
  value       = aws_eip.nat.public_ip
}

output "internet_gateway_id" {
  description = "Internet Gateway ID"
  value       = aws_internet_gateway.main.id
}

output "rds_subnet_group_name" {
  description = "RDS subnet group name"
  value       = aws_db_subnet_group.main.name
}
