# =============================================================================
# MAIN.TF - Secure Cloud Landing Zone
# =============================================================================
# This is the root Terraform module that orchestrates the entire landing zone.
# It calls child modules for each major component.
#
# SECURITY PHILOSOPHY:
# - Defense in depth: Multiple layers of security
# - Least privilege: Minimum necessary permissions
# - Audit everything: Comprehensive logging
# - Secure by default: Safe configurations out of the box

# =============================================================================
# DATA SOURCES
# =============================================================================
# Data sources allow us to read information from AWS without creating resources.
# We use them to get account IDs and verify existing resources.

# Get current caller identity for management account
data "aws_caller_identity" "management" {
  provider = aws.management
}

# Get security account ID - used for cross-account references
data "aws_caller_identity" "security" {
  provider = aws.security
}

# Get workload account ID - used for cross-account references
data "aws_caller_identity" "workload" {
  provider = aws.workload
}

# =============================================================================
# MODULE: AWS ORGANIZATION
# =============================================================================
# The AWS Organization provides centralized management of multiple AWS accounts.
# Security Benefit:
# - Consolidated billing for cost tracking
# - Service Control Policies (SCPs) to enforce security baselines
# - Simplified permission management via organizational units

module "organization" {
  source = "./modules/organization"

  providers = {
    aws = aws.management
  }

  # The organization is managed from the management account
  management_account_id = data.aws_caller_identity.management.account_id

  environment = var.environment

  # Security Account is dedicated to security tooling
  # This separation ensures security tools can't be compromised by workloads
  security_account_email = "security@yourcompany.com"
  security_account_name  = "security-tools"

  # Workload Account hosts application resources
  # Keeping workloads isolated from security tools reduces blast radius
  workload_account_email = "workload@yourcompany.com"
  workload_account_name = "application-workloads"
}

# =============================================================================
# MODULE: NETWORK (VPC)
# =============================================================================
# The VPC module creates the network infrastructure with proper segmentation.
# Security Architecture:
# - Public subnets: Only for load balancers (directly internet accessible)
# - Private subnets: For application servers (no direct internet access)
# - NAT Gateway: Allows private instances to initiate outbound connections
#
# Why this matters:
# If an attacker compromises an application server, they can't receive
# connections from the internet. They can only make outbound connections
# through the NAT, limiting what they can do.

module "network" {
  source = "./modules/network"

  providers = {
    aws = aws.workload
  }

  # Network Configuration
  vpc_cidr             = var.vpc_cidr
  availability_zones   = var.availability_zones
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs

  environment = var.environment

  # Single NAT Gateway for cost efficiency in dev
  # Production should have one NAT per AZ for high availability
  single_nat_gateway = var.environment == "dev" ? true : false
}

# =============================================================================
# MODULE: SECURITY (S3 + Security Groups)
# =============================================================================
# This module implements data protection and network security controls.
# Security Groups: Instance-level firewalls (stateful)
# S3 Buckets: Encrypted storage with versioning and public access blocked
#
# Key Security Features:
# 1. S3 Encryption: AES-256 encryption at rest (AWS-managed keys)
# 2. S3 Versioning: Protects against accidental deletion/malicious overwrites
# 3. S3 Public Access Block: Prevents data leakage
# 4. Security Groups: Least-privilege access control

module "security" {
  source = "./modules/security"

  providers = {
    aws = aws.workload
  }

  environment = var.environment

  # S3 Configuration
  # The log archive bucket is in the security account for isolation
  log_archive_bucket_account_id = data.aws_caller_identity.security.account_id

  # S3 bucket names - must be globally unique
  log_archive_bucket_name = var.log_archive_bucket_name != "" ? var.log_archive_bucket_name : "clz-log-archive-${data.aws_caller_identity.workload.account_id}-${var.environment}"
  workload_bucket_name    = var.workload_bucket_name != "" ? var.workload_bucket_name : "clz-workload-data-${data.aws_caller_identity.workload.account_id}-${var.environment}"

  # Security Group Configuration
  # NO default CIDRs - must be explicitly provided
  # This forces operators to think about access control
  allowed_admin_cidrs = var.allowed_admin_cidrs
  allowed_http_cidrs  = var.allowed_http_cidrs

  # VPC references for security group creation
  vpc_id = module.network.vpc_id

  # Reference private subnet IDs for RDS security group
  private_subnet_ids = module.network.private_subnet_ids

  # MFA Delete for log bucket
  enable_mfa_delete = var.enable_mfa_delete

  # S3 Lifecycle - incomplete multipart uploads waste space and can be exploited
  lifecycle_rule_enabled = true
}

# =============================================================================
# MODULE: LOGGING (CloudTrail)
# =============================================================================
# CloudTrail records all AWS API calls, providing:
# 1. Audit Trail: Who did what, when, from where
# 2. Compliance: Evidence for regulatory requirements
# 3. Security: Detect anomalous API activity
# 4. Troubleshooting: Debug operational issues
#
# Security Design:
# - Multi-Region trail: Captures activity across all regions (defense in depth)
# - Log file validation: Detects tampering with log files
# - Centralized logging: All logs go to security account (isolation)

module "logging" {
  source = "./modules/logging"

  providers = {
    aws.management = aws.management
    aws.security   = aws.security
  }

  environment = var.environment

  # CloudTrail is managed from the management account
  # But logs are stored in the security account (separation of duties)
  management_account_id  = data.aws_caller_identity.management.account_id
  security_account_id    = data.aws_caller_identity.security.account_id
  workload_account_id    = data.aws_caller_identity.workload.account_id

  # S3 bucket for CloudTrail logs
  cloudtrail_s3_bucket_arn = module.security.log_archive_bucket_arn

  # CloudTrail Configuration
  enable_cloudtrail          = var.enable_cloudtrail
  log_retention_days         = var.log_retention_days
  is_multi_region_trail      = true  # Capture all regions
  enable_log_file_validation = true # Detect log tampering
}

# =============================================================================
# MODULE: IAM (Roles and Policies)
# =============================================================================
# IAM module implements least-privilege access control.
# Security Principles:
# 1. No long-term access keys - use role assumption instead
# 2. Specific actions only - never "*" except in rare cases
# 3. Resource-level permissions where possible
# 4. Condition keys for additional context (e.g., MFA)
#
# Why Role Assumption?
# Access keys can be leaked, stolen, or committed to git.
# Role assumption uses temporary credentials that expire automatically.

module "iam" {
  source = "./modules/iam"

  providers = {
    aws = aws.workload
  }

  environment = var.environment

  # Allow workload account to read logs from security account
  log_archive_bucket_arn = module.security.log_archive_bucket_arn

  # Account IDs for cross-account role policies
  workload_account_id = data.aws_caller_identity.workload.account_id
  security_account_id = data.aws_caller_identity.security.account_id

  # VPC ID for IAM policy conditions
  # We can restrict EC2 instance roles to only work within our VPC
  allowed_vpc_id = module.network.vpc_id
}

# =============================================================================
# MODULE: AWS CONFIG
# =============================================================================
# AWS Config provides continuous compliance monitoring.
# Security Benefits:
# 1. Detect configuration changes that introduce security risks
# 2. Automated compliance checking against security baselines
# 3. Configuration history for forensic analysis
# 4. Remediation automation (with SSM Automation documents)

module "aws_config" {
  source = "./modules/aws-config"

  providers = {
    aws = aws.security
  }

  environment = var.environment

  # AWS Config recorder is deployed to workload account
  # but managed from security account for centralized view
  workload_account_id = data.aws_caller_identity.workload.account_id
  workload_vpc_id     = module.network.vpc_id

  # S3 bucket for Config data
  config_bucket_arn = module.security.log_archive_bucket_arn

  enable_aws_config = var.enable_aws_config
}
