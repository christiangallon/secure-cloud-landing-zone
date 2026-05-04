# =============================================================================
# DEV ENVIRONMENT VARIABLES
# =============================================================================
# Development environment configuration for Secure Cloud Landing Zone.
# Use for testing and development - NOT for production data.
#
# SECURITY NOTE:
# Dev environment has relaxed settings for ease of use.
# Production should use stricter settings.

# -----------------------------------------------------------------------------
# COMMON SETTINGS
# -----------------------------------------------------------------------------

aws_region  = "us-east-1"
environment  = "dev"

# Cross-account role ARNs (REQUIRED - override these values)
# Format: arn:aws:iam::ACCOUNT-ID:role/ROLE-NAME
# Leave empty if running in a single account

external_id         = "dev-external-id"  # Replace with secure random value
management_role_arn  = ""  # Override: arn:aws:iam::111111111111:role/TerraformRole
security_role_arn   = ""  # Override: arn:aws:iam::222222222222:role/TerraformRole
workload_role_arn   = ""  # Override: arn:aws:iam::333333333333:role/TerraformRole

# -----------------------------------------------------------------------------
# NETWORK CONFIGURATION
# -----------------------------------------------------------------------------

vpc_cidr             = "10.0.0.0/16"
availability_zones   = ["us-east-1a", "us-east-1b"]
public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
private_subnet_cidrs = ["10.0.3.0/24", "10.0.4.0/24"]

# -----------------------------------------------------------------------------
# S3 BUCKET CONFIGURATION
# -----------------------------------------------------------------------------

# Bucket names (must be globally unique - include account ID)
log_archive_bucket_name = "clz-log-archive-dev-123456789012"
workload_bucket_name    = "clz-workload-data-dev-123456789012"

# Log retention: 30 days for dev (reduce cost)
log_retention_days = 30

# MFA Delete: Disabled for dev (requires MFA device setup)
enable_mfa_delete = false

# -----------------------------------------------------------------------------
# SECURITY GROUPS
# -----------------------------------------------------------------------------

# Administrative access: NO default! Must be explicitly set.
# Example: ["10.0.0.0/24"] for VPN access only
allowed_admin_cidrs = []

# HTTP/HTTPS: Open for development (ALB only)
allowed_http_cidrs = ["0.0.0.0/0"]

# -----------------------------------------------------------------------------
# FEATURE FLAGS
# -----------------------------------------------------------------------------

enable_cloudtrail  = true
enable_aws_config  = true

# -----------------------------------------------------------------------------
# TAGS
# -----------------------------------------------------------------------------

tags = {
  Environment = "dev"
  CostCenter  = "Development"
  Owner       = "DevOps Team"
}
