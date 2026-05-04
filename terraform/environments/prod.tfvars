# =============================================================================
# PRODUCTION ENVIRONMENT VARIABLES
# =============================================================================
# Production environment configuration for Secure Cloud Landing Zone.
#
# SECURITY NOTE:
# Production uses strictest settings for maximum security.
# Review each setting carefully before deployment.
#
# COMPLIANCE:
# This configuration supports: SOC 2, PCI DSS, ISO 27001

# -----------------------------------------------------------------------------
# COMMON SETTINGS
# -----------------------------------------------------------------------------

aws_region  = "us-east-1"
environment  = "prod"

# Cross-account role ARNs (REQUIRED - MUST override)
# Production should use dedicated Terraform roles per account
# Format: arn:aws:iam::ACCOUNT-ID:role/ROLE-NAME

external_id         = ""  # MUST SET: Generate unique external ID per environment
management_role_arn = ""  # MUST SET: arn:aws:iam::111111111111:role/TerraformRole
security_role_arn   = ""  # MUST SET: arn:aws:iam::222222222222:role/TerraformRole
workload_role_arn   = ""  # MUST SET: arn:aws:iam::333333333333:role/TerraformRole

# -----------------------------------------------------------------------------
# NETWORK CONFIGURATION
# -----------------------------------------------------------------------------

vpc_cidr             = "10.0.0.0/16"
availability_zones   = ["us-east-1a", "us-east-1b", "us-east-1c"]
public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
private_subnet_cidrs = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

# Note: Prod uses 3 AZs for high availability
# NAT Gateway: Consider NAT per AZ for HA (higher cost)

# -----------------------------------------------------------------------------
# S3 BUCKET CONFIGURATION
# -----------------------------------------------------------------------------

# Bucket names (must be globally unique)
log_archive_bucket_name = "clz-log-archive-prod-123456789012"
workload_bucket_name    = "clz-workload-data-prod-123456789012"

# Log retention: 365 days for compliance
log_retention_days = 365

# MFA Delete: ENABLED for production
# WARNING: Requires MFA device to be configured on the account
# Once enabled, bucket deletion requires MFA authentication
enable_mfa_delete = true

# -----------------------------------------------------------------------------
# SECURITY GROUPS
# -----------------------------------------------------------------------------

# Administrative access: RESTRICT to VPN/Direct Connect ONLY
# NEVER allow SSH/RDP from 0.0.0.0/0 in production
allowed_admin_cidrs = []

# HTTP/HTTPS: Open for ALB (protected by WAF recommended)
allowed_http_cidrs = ["0.0.0.0/0"]

# -----------------------------------------------------------------------------
# FEATURE FLAGS
# -----------------------------------------------------------------------------

enable_cloudtrail  = true
enable_aws_config  = true

# -----------------------------------------------------------------------------
# ADDITIONAL PRODUCTION RECOMMENDATIONS
# -----------------------------------------------------------------------------
# 1. Enable AWS Security Hub for centralized security findings
# 2. Enable AWS GuardDuty for threat detection
# 3. Enable AWS WAF for web application protection
# 4. Enable AWS Shield for DDoS protection
# 5. Configure AWS Backup for automated backups
# 6. Enable RDS Auto Backups with 7-day retention
# 7. Use AWS KMS with customer-managed keys (CMK)
# 8. Enable VPC Flow Logs for network monitoring
# 9. Configure CloudWatch Alarms with SNS for notifications
# 10. Enable AWS Secrets Manager for credential management

# -----------------------------------------------------------------------------
# TAGS
# -----------------------------------------------------------------------------

tags = {
  Environment = "prod"
  CostCenter  = "Production"
  Owner       = "Security Team"
  Compliance  = "SOC2,PCI"
}
