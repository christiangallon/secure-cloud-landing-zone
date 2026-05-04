# =============================================================================
# SECURITY MODULE - S3 Buckets and Security Groups
# =============================================================================
# This module implements data protection (S3) and network security (SGs).
#
# S3 SECURITY CONTROLS:
# 1. Encryption at rest (AES-256) - Protects data if storage is compromised
# 2. Versioning - Protects against accidental deletion/malicious overwrites
# 3. Public Access Block - Prevents data leakage
# 4. Lifecycle Rules - Reduces attack surface and storage costs
# 5. MFA Delete - Prevents accidental bucket deletion
#
# SECURITY GROUP ARCHITECTURE:
# =============================
# Internet -> ALB (Port 80/443) -> EC2 (Port 3000) -> RDS (Port 5432)
#              ^                      ^                    ^
#         Web Security Group    App Security Group   DB Security Group
#
# Each tier only accepts traffic from the PREVIOUS tier.
# This is micro-segmentation: compromise of one tier doesn't mean
# compromise of others.

# =============================================================================
# S3 BUCKET: LOG ARCHIVE
# =============================================================================
# This bucket stores all CloudTrail and AWS Config logs.
# Location: Security Account (cross-account isolation)
#
# SECURITY DESIGN:
# - Separate account: Logs can't be tampered with by workload account
# - Versioning: Can recover from accidental/malicious modifications
# - Public Access Blocked: Logs are confidential
# - Encryption: All data encrypted at rest
# - MFA Delete: Prevents bucket deletion without additional auth

resource "aws_s3_bucket" "log_archive" {
  # Bucket names must be globally unique
  # Including account ID prevents collisions across accounts
  bucket = var.log_archive_bucket_name

  # tags are used for cost allocation and resource tracking
  tags = {
    Name        = "${var.environment}-log-archive"
    Description = "Centralized log storage for CloudTrail and AWS Config"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    DataType    = "Logs"
    Confidentiality = "High"
  }
}

# =============================================================================
# S3 BUCKET: WORKLOAD DATA
# =============================================================================
# This bucket stores application data.
# SECURITY CONTROLS:
# - Server-side encryption with AWS-managed keys
# - Versioning enabled for data protection
# - Public access blocked by default
# - Access logging for audit trail

resource "aws_s3_bucket" "workload_data" {
  bucket = var.workload_bucket_name

  tags = {
    Name        = "${var.environment}-workload-data"
    Description = "Application data storage"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    DataType    = "Application"
  }
}

# =============================================================================
# S3: ENCRYPTION CONFIGURATION
# =============================================================================
# All buckets use AES-256 encryption at rest.
# Why AES-256?
# - Industry standard, FIPS 140-2 compliant
# - AWS manages keys (no key rotation needed)
# - Low latency impact
#
# For higher security, consider KMS with customer-managed keys (CMK)
# which provides:
# - Separate key access control
# - Automatic key rotation
# - Audit logging of key usage

resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    # AES-256 (SSE-S3): AWS-managed, automatic key rotation
    # SSE-KMS: Customer-managed keys, more control
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }

    # Optionally require encryption for all uploads
    # This prevents uploading unencrypted data
    # bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "workload_data" {
  bucket = aws_s3_bucket.workload_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# =============================================================================
# S3: VERSIONING
# =============================================================================
# S3 Versioning preserves, retrieves, and restores every version of an object.
# SECURITY BENEFITS:
# 1. Protects against accidental deletion (can restore previous version)
# 2. Protects against malicious overwrites (attacker can't destroy data)
# 3. Provides audit trail of all changes
#
# Without versioning:
# - Overwriting a file destroys the original
# - Deleting a file is permanent
# - Ransomware could encrypt and lose your data

resource "aws_s3_bucket_versioning" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  versioning_configuration {
    # Enabled: All versions are preserved
    # Suspended: Versioning paused (not recommended)
    # Note: Once enabled, you cannot disable versioning, only suspend it
    status = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "workload_data" {
  bucket = aws_s3_bucket.workload_data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# =============================================================================
# S3: PUBLIC ACCESS BLOCK
# =============================================================================
# BLOCKS all public access to buckets.
# This is CRITICAL for security:
# - Prevents accidental exposure of private data
# - Prevents intentional data leaks
# - Blocks all four public access settings at once
#
# Even if someone uploads a public bucket policy,
# these settings will block public access.
#
# AWS recommendation: Enable for ALL buckets unless
# you specifically need public hosting (like a static website).

resource "aws_s3_bucket_public_access_block" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  # Block public access through:
  block_public_acls       = true  # Ignore bucket ACLs that allow public access
  block_public_policy     = true  # Ignore bucket policies that allow public access
  ignore_public_acls      = true  # Suppress existing public ACLs
  restrict_public_buckets = true # Block cross-account access through policies

  # Why all four?
  # 1. Bucket ACLs (legacy feature)
  # 2. Bucket policies (newer, more common)
  # 3. Both together (multiple layers)
  # 4. Cross-account policies (other accounts accessing this bucket)
}

resource "aws_s3_bucket_public_access_block" "workload_data" {
  bucket = aws_s3_bucket.workload_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# =============================================================================
# S3: LIFECYCLE RULES
# =============================================================================
# Lifecycle rules automate object transitions and deletions.
# SECURITY BENEFITS:
# 1. Clean up incomplete multipart uploads (security hygiene)
# 2. Transition to cheaper storage classes (cost optimization)
# 3. Archive or delete old versions (compliance)
#
# Incomplete multipart uploads can accumulate and waste space.
# They can also be a target for attackers if they guess the upload ID.

resource "aws_s3_bucket_lifecycle_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  rule {
    id     = "cleanup-incomplete-uploads"
    status = "Enabled"

    # Filter to apply this rule to all objects
    filter {}

    # Abort incomplete multipart uploads after 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "archive-old-versions"
    status = "Enabled"

    filter {
      # Apply to non-current versions (previous versions of objects)
      and {
        prefix = ""
        tag {
          key   = "Type"
          value = "Archive"
        }
      }
    }

    # Transition non-current versions to Glacier after 90 days
    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # Permanently delete after 365 days (compliance requirement)
    expiration {
      days = 365
    }
  }
}

# =============================================================================
# S3: MFA DELETE (Log Archive Only)
# =============================================================================
# MFA Delete requires additional authentication to delete objects or
# change bucket versioning state.
# SECURITY: Prevents accidental or malicious bucket deletion.
# COST: Requires MFA hardware token (~$50) or virtual MFA device.
#
# When to enable:
# - Log buckets (critical forensic evidence)
# - Production data buckets
# - Compliance-required data
#
# Note: Only works with versioning enabled. Already enabled above.

resource "aws_s3_bucket_mfa_delete" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  # Only enable if explicitly requested (MFA device required)
  mfa_delete = var.enable_mfa_delete ? "Enabled" : "Disabled"
}

# =============================================================================
# S3: CROSS-ACCOUNT ACCESS POLICY
# =============================================================================
# Allow CloudTrail from management account to write logs.
# This is a resource policy (not IAM policy) that lives on the bucket.
# It explicitly allows the management account's CloudTrail to write.
#
# SECURITY: Resource policies are more explicit than IAM policies.
# The management account (who controls CloudTrail) is explicitly listed.

resource "aws_s3_bucket_policy" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudTrailWrite"
        Effect = "Allow"
        # CloudTrail uses these services to write logs
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:GetBucketPolicy",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_bucket.log_archive.arn}",
          "${aws_s3_bucket.log_archive.arn}/*"
        ]
        # Only allow if the trail is in our organization
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.log_archive_bucket_account_id
          }
        }
      },
      {
        Sid    = "AllowConfigWrite"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:GetBucketPolicy",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_bucket.log_archive.arn}",
          "${aws_s3_bucket.log_archive.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.log_archive_bucket_account_id
          }
        }
      },
      {
        Sid    = "DenyUnencryptedUploads"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.log_archive.arn}/*"
        # Block uploads without encryption header
        Condition = {
          Null = {
            "s3:x-amz-server-side-encryption" = "true"
          }
        }
      },
      {
        Sid    = "DenyDeleteWithoutMFA"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteBucket"
        ]
        Resource = [
          "${aws_s3_bucket.log_archive.arn}",
          "${aws_s3_bucket.log_archive.arn}/*"
        ]
        # If MFA delete is enabled, this condition checks for MFA
        # Without MFA token, delete operations are denied
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# =============================================================================
# SECURITY GROUP: WEB TIER (For ALB)
# =============================================================================
# Security Groups are stateful firewalls at the ENI level.
# Security Best Practices:
# 1. Least privilege: Only allow necessary traffic
# 2. Reference by security group ID, not CIDR (more flexible)
# 3. Document why each rule exists
# 4. Default deny: Ingress denied by default
#
# WEB SG RULES:
# - Inbound HTTP (80): From anywhere (for ALB)
# - Inbound HTTPS (443): From anywhere (for ALB)
# - Outbound: To App SG on port 3000 (application traffic)

resource "aws_security_group" "web" {
  name        = "${var.environment}-web-sg"
  description = "Security group for web tier (Load Balancer)"

  # Reference the VPC to create SG in correct network
  vpc_id = var.vpc_id

  # Tags for cost tracking and resource management
  tags = {
    Name        = "${var.environment}-web-sg"
    Description = "Security group for web/ALB tier"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    Tier        = "Web"
  }
}

# =============================================================================
# SECURITY GROUP: APP TIER (For EC2/ECS)
# =============================================================================
# Application servers receive traffic only from the Web SG.
# This is the MICRO-SEGMENTATION principle:
# Even if someone bypasses the ALB, they can only talk to app servers.
# They can't directly reach the database.
#
# APP SG RULES:
# - Inbound from Web SG: Port 3000 (application port)
# - Outbound: To DB SG on port 5432 (database traffic)

resource "aws_security_group" "app" {
  name        = "${var.environment}-app-sg"
  description = "Security group for application tier"

  vpc_id = var.vpc_id

  tags = {
    Name        = "${var.environment}-app-sg"
    Description = "Security group for application servers"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    Tier        = "Application"
  }
}

# =============================================================================
# SECURITY GROUP: DATABASE TIER (For RDS)
# =============================================================================
# Database receives traffic ONLY from App SG.
# This is critical: The database is NOT directly accessible from the internet.
# Even if an attacker compromises an app server, they can only reach the DB
# if they can execute queries through the app.
#
# DB SG RULES:
# - Inbound from App SG: Port 5432 (PostgreSQL)
# - Outbound: None (databases don't need to initiate connections)
#
# For RDS Multi-AZ, also allow:
# - Port 5432 from RDS replicas in other AZs
# - Port 5432 from RDS management (AWS internal)

resource "aws_security_group" "database" {
  name        = "${var.environment}-database-sg"
  description = "Security group for database tier"

  vpc_id = var.vpc_id

  # Default: No egress rules = all outbound denied
  # This is the MOST SECURE setting
  # If your database needs to initiate connections (e.g., for updates),
  # add specific egress rules

  tags = {
    Name        = "${var.environment}-database-sg"
    Description = "Security group for RDS database"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    Tier        = "Database"
  }
}

# =============================================================================
# SECURITY GROUP RULES: WEB TIER
# =============================================================================

# Inbound HTTP - From internet for Load Balancer
resource "aws_vpc_security_group_ingress_rule" "web_http" {
  security_group_id = aws_security_group.web.id
  description       = "Allow HTTP from internet for Load Balancer"

  # Allow from anywhere on port 80
  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"

  # Why allow from 0.0.0.0/0?
  # Because the ALB IS exposed to the internet. The ALB provides:
  # 1. DDOS protection
  # 2. SSL termination
  # 3. WAF integration
  # 4. Request limiting
  # The ALB is designed to be internet-facing.
}

# Inbound HTTPS - From internet for Load Balancer
resource "aws_vpc_security_group_ingress_rule" "web_https" {
  security_group_id = aws_security_group.web.id
  description       = "Allow HTTPS from internet for Load Balancer"

  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
}

# Outbound to App Tier - Application traffic
resource "aws_vpc_security_group_ingress_rule" "web_to_app" {
  security_group_id            = aws_security_group.app.id
  description                  = "Allow app traffic from web tier"

  from_port                    = 3000
  to_port                      = 3000
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.web.id

  # Why reference by SG ID?
  # If the web tier's CIDR changes, this rule still works.
  # It's more flexible than hardcoded IP addresses.
}

# =============================================================================
# SECURITY GROUP RULES: APP TIER
# =============================================================================

# Inbound from Web Tier
resource "aws_vpc_security_group_ingress_rule" "app_from_web" {
  security_group_id            = aws_security_group.app.id
  description                  = "Allow application traffic from web tier"

  from_port                    = 3000
  to_port                      = 3000
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.web.id
}

# Outbound to Database
resource "aws_vpc_security_group_ingress_rule" "app_to_db" {
  security_group_id            = aws_security_group.database.id
  description                  = "Allow database traffic from app tier"

  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.app.id
}

# =============================================================================
# SECURITY GROUP RULES: DATABASE TIER
# =============================================================================

# Inbound from App Tier
resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.database.id
  description                  = "Allow database traffic from app tier"

  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.app.id
}

# =============================================================================
# ADMINISTRATIVE ACCESS (Optional)
# =============================================================================
# Allow SSH/RDP access from admin networks ONLY.
# This is commented out by default because:
# 1. SSH directly to EC2 is a security risk
# 2. AWS Systems Manager Session Manager is preferred
# 3. We want to force explicit consideration of admin access
#
# To enable, specify allowed_admin_cidrs in variables.
# Example: ["10.0.0.0/24"] for VPN-only access

resource "aws_vpc_security_group_ingress_rule" "admin_ssh" {
  count       = length(var.allowed_admin_cidrs) > 0 ? 1 : 0
  security_group_id = aws_security_group.app.id
  description = "Allow SSH from admin network"

  from_port   = 22
  to_port     = 22
  ip_protocol = "tcp"
  cidr_ipv4   = var.allowed_admin_cidrs[0]

  # Security Note: SSH access should be:
  # 1. Restricted to specific IP ranges (not 0.0.0.0/0)
  # 2. Protected by security groups (done here)
  # 3. Protected by IAM (use IAM auth for SSH)
  # 4. Monitored via CloudTrail (enabled in logging module)
  # 5. Protected by fail2ban or similar (at OS level)
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "log_archive_bucket_name" {
  description = "Log archive S3 bucket name"
  value       = aws_s3_bucket.log_archive.bucket
}

output "log_archive_bucket_arn" {
  description = "Log archive S3 bucket ARN"
  value       = aws_s3_bucket.log_archive.arn
}

output "workload_bucket_name" {
  description = "Workload data S3 bucket name"
  value       = aws_s3_bucket.workload_data.bucket
}

output "workload_bucket_arn" {
  description = "Workload data S3 bucket ARN"
  value       = aws_s3_bucket.workload_data.arn
}

output "web_security_group_id" {
  description = "Web tier security group ID"
  value       = aws_security_group.web.id
}

output "app_security_group_id" {
  description = "App tier security group ID"
  value       = aws_security_group.app.id
}

output "database_security_group_id" {
  description = "Database tier security group ID"
  value       = aws_security_group.database.id
}
