# =============================================================================
# PROVIDERS CONFIGURATION
# =============================================================================
# This file configures the AWS providers for multi-account deployment.
# Security Note: We use role assumption to avoid storing long-term credentials.
# Each account has its own provider configured to assume a specific role.

terraform {
  # Require Terraform 1.0+ for module syntax and improved state management
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"  # Pin to 5.x for stability
    }
  }

  # Remote state is recommended for team environments
  # Uncomment below for production use with S3 backend
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "secure-landing-zone/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-state-lock"
  # }
}

# =============================================================================
# PROVIDER: MANAGEMENT ACCOUNT
# =============================================================================
# The management account is the payer account and has full access.
# Security Best Practice: Use this provider only for organization-level
# resources like SCPs, organizational units, and aggregated CloudTrail.

provider "aws" {
  alias  = "management"
  region = var.aws_region

  # SECURITY: Assume role with external ID for cross-account access
  # This prevents unauthorized access if the role ARN is leaked
  assume_role {
    role_arn     = var.management_role_arn
    external_id  = var.external_id
    session_name = "terraform-management-session"
  }

  # Default tags help with cost allocation and resource tracking
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = "SecureCloudLandingZone"
    }
  }
}

# =============================================================================
# PROVIDER: SECURITY ACCOUNT
# =============================================================================
# The security account hosts security tooling and acts as a log archive.
# This account should have NO application workloads - only security tools.
# Why: Separation of duties ensures security tools can't be compromised by apps.

provider "aws" {
  alias  = "security"
  region = var.aws_region

  assume_role {
    role_arn     = var.security_role_arn
    external_id  = var.external_id
    session_name = "terraform-security-session"
  }

  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = "SecureCloudLandingZone"
      AccountType = "Security"
    }
  }
}

# =============================================================================
# PROVIDER: WORKLOAD ACCOUNT
# =============================================================================
# The workload account hosts application resources.
# Security Model: This account has the LEAST privileges of the three.
# Resources here should assume roles from the security account for any
# cross-account access (like reading CloudTrail logs).

provider "aws" {
  alias  = "workload"
  region = var.aws_region

  assume_role {
    role_arn     = var.workload_role_arn
    external_id  = var.external_id
    session_name = "terraform-workload-session"
  }

  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = "SecureCloudLandingZone"
      AccountType = "Workload"
    }
  }
}
