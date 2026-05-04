# =============================================================================
# VARIABLES - Input definitions for the Secure Cloud Landing Zone
# =============================================================================
# This file contains all input variables with descriptions explaining
# WHY each variable exists and security implications.

# =============================================================================
# COMMON VARIABLES
# =============================================================================

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"

  # Security Note: us-east-1 is chosen because:
  # 1. Most AWS services launch here first
  # 2. CloudTrail defaults to this region
  # 3. Some compliance frameworks require it
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

# =============================================================================
# CROSS-ACCOUNT ACCESS VARIABLES
# =============================================================================
# Security Best Practice: Use external IDs when assuming cross-account roles.
# This mitigates the confused deputy problem where an attacker could
# trick your role into being used against a different resource.

variable "external_id" {
  description = "External ID for cross-account role assumption"
  type        = string
  sensitive   = true  # Won't show in terraform plan output
  default     = ""    # Override in environment-specific tfvars

  # Why external_id matters:
  # Without it, anyone who knows your role ARN could assume it.
  # With it, they also need the external_id which you control.
}

variable "management_role_arn" {
  description = "IAM Role ARN to assume for management account operations"
  type        = string
  default     = ""  # Format: arn:aws:iam::111111111111:role/TerraformRole
}

variable "security_role_arn" {
  description = "IAM Role ARN to assume for security account operations"
  type        = string
  default     = ""
}

variable "workload_role_arn" {
  description = "IAM Role ARN to assume for workload account operations"
  type        = string
  default     = ""
}

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    # AWS recommends /16 or smaller for VPCs
    # Too large = wasted IP addresses, too small = insufficient hosts
    condition     = cidrsubnet(var.vpc_cidr, 0, 0) == var.vpc_cidr
    error_message = "Must be a valid CIDR block (e.g., 10.0.0.0/16)."
  }
}

variable "availability_zones" {
  description = "Availability zones for the VPC"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]

  # Security Note: Using multiple AZs enables:
  # 1. High Availability - automatic failover
  # 2. Fault Isolation - one AZ failure doesn't affect others
  # 3. Redundancy for critical workloads
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (one per AZ)"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

# =============================================================================
# S3 BUCKET CONFIGURATION
# =============================================================================

variable "log_archive_bucket_name" {
  description = "S3 bucket name for centralized log storage"
  type        = string
  default     = ""

  # Security: This bucket stores ALL CloudTrail logs from all accounts.
  # It's critical for forensic analysis and compliance.
  # The bucket name should be globally unique.
}

variable "workload_bucket_name" {
  description = "S3 bucket name for workload data"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Number of days to retain CloudTrail logs"
  type        = number
  default     = 30  # Dev default; prod should be 365+

  validation {
    condition     = var.log_retention_days >= 1 && var.log_retention_days <= 3650
    error_message = "Retention must be between 1 and 3650 days."
  }

  # Compliance Note:
  # SOC 2: Typically 1 year
  # PCI DSS: 1 year
  # HIPAA: 6 years
  # Choose based on your compliance requirements
}

variable "enable_mfa_delete" {
  description = "Require MFA for S3 bucket deletion"
  type        = bool
  default     = false

  # Security: This prevents accidental or malicious bucket deletion.
  # When enabled, you need MFA + valid credentials to delete the bucket
  # or objects within it. Critical for production log buckets.
}

# =============================================================================
# FEATURE FLAGS
# =============================================================================

variable "enable_cloudtrail" {
  description = "Enable CloudTrail logging across all accounts"
  type        = bool
  default     = true

  # Security: CloudTrail provides:
  # 1. Audit trail of all API calls
  # 2. Compliance evidence
  # 3. Security analysis
  # 4. Operational troubleshooting
  # NEVER disable in production!
}

variable "enable_aws_config" {
  description = "Enable AWS Config for compliance monitoring"
  type        = bool
  default     = true

  # Security: AWS Config provides:
  # 1. Configuration history and changes
  # 2. Compliance rules evaluation
  # 3. Security analysis
  # 4. Automated remediation (with SSM)
}

# =============================================================================
# SECURITY GROUP CONFIGURATION
# =============================================================================

variable "allowed_admin_cidrs" {
  description = "CIDR blocks allowed for administrative access"
  type        = list(string)
  default     = []  # NO default! Must be explicitly specified.

  # Security: Administrative access should NEVER have a default.
  # This forces operators to explicitly define allowed networks.
  # Best practice: Use AWS SSM Session Manager instead of SSH.
}

variable "allowed_http_cidrs" {
  description = "CIDR blocks allowed for HTTP/HTTPS traffic"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Internet accessible by default for ALB

  # Note: This is intentionally open for the ALB.
  # The ALB itself provides DDOS protection and WAF can be added.
  # Private instances are NOT directly accessible.
}
