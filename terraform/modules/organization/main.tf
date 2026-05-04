# =============================================================================
# ORGANIZATION MODULE
# =============================================================================
# This module manages AWS Organizations for multi-account governance.
#
# SECURITY BENEFITS OF AWS ORGANIZATIONS:
# 1. Centralized account management
# 2. Service Control Policies (SCPs) for security baselines
# 3. Consolidated billing for cost tracking
# 4. Hierarchical grouping with Organizational Units (OUs)
#
# ARCHITECTURE:
# Organization Root
#   └── Security OU
#       └── Security Account
#   └── Workloads OU
#       └── Workload Account

# =============================================================================
# DATA SOURCES
# =============================================================================

# Get existing organization info (if already created)
data "aws_organizations_organization" "this" {
  # This data source will fail if no organization exists
  # In that case, you need to create the organization manually first
}

# =============================================================================
# RESOURCE: ORGANIZATIONAL UNIT - SECURITY
# =============================================================================
# OUs group accounts for unified policy application.
# Security OU contains security tooling accounts.
# Benefit: SCPs applied here affect ALL security accounts automatically.

resource "aws_organizations_organizational_unit" "security" {
  name      = "security-tools"
  parent_id = aws_organizations_organization.this.roots[0].id

  tags = {
    Description = "Security tooling accounts"
    ManagedBy   = "Terraform"
  }
}

# =============================================================================
# RESOURCE: ORGANIZATIONAL UNIT - WORKLOADS
# =============================================================================
# Workloads OU contains application accounts.
# Keeping workloads separate from security tools is CRITICAL:
# - If an application is compromised, attackers can't reach security tools
# - Security tools have independent access controls
# - Audit teams can access workload logs without affecting production

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "application-workloads"
  parent_id = aws_organizations_organization.this.roots[0].id

  tags = {
    Description = "Application workload accounts"
    ManagedBy   = "Terraform"
  }
}

# =============================================================================
# RESOURCE: SERVICE CONTROL POLICY - DENY DELETE
# =============================================================================
# SCPs restrict actions across all accounts in an OU.
# This SCP prevents deletion of critical security resources.
# Why: Adds another layer of protection beyond IAM permissions.
# Even if someone has admin access, they can't delete these resources.

resource "aws_organizations_policy" "deny_delete" {
  name        = "DenyDeleteCriticalResources"
  description = "Prevents deletion of CloudTrail, Config, and S3 buckets"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyCriticalServiceDeletion"
        Effect = "Deny"
        NotAction = [
          # Allow everything except deletion of security services
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "s3:DeleteBucket",
          "s3:PutBucketVersioning",
          "config:DeleteConfigRule",
          "config:StopConfigurationRecorder",
          "iam:DeleteRole",
          "iam:DeletePolicy"
        ]
        Resource = "*"
        Condition = {
          # Only apply to resources tagged with this project
          StringEquals = {
            "aws:ResourceTag/Project" = "SecureCloudLandingZone"
          }
        }
      }
    ]
  })

  # Do NOT auto-attach - we attach selectively
  skip_destroy = false
}

# =============================================================================
# RESOURCE: SERVICE CONTROL POLICY - REQUIRE ENCRYPTION
# =============================================================================
# This SCP ensures ALL S3 buckets must have encryption enabled.
# Why: Prevents accidental creation of unencrypted data stores.
# Compliance: Helps meet encryption requirements for SOC2, PCI, etc.

resource "aws_organizations_policy" "require_encryption" {
  name        = "RequireEncryptionAtRest"
  description = "Requires S3 buckets to have encryption enabled"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RequireSSE"
        Effect = "Deny"
        NotAction = [
          # Allow all S3 actions except those that bypass encryption
          "s3:*"
        ]
        Resource = [
          "arn:aws:s3:::*"
        ]
        # Deny if bucket doesn't have encryption
        Condition = {
          Bool = {
            "s3:x-amz-server-side-encryption" = "false"
          }
        }
      },
      {
        Sid    = "AllowS3WithEncryption"
        Effect = "Allow"
        Action = [
          "s3:*"
        ]
        Resource = [
          "arn:aws:s3:::*"
        ]
      }
    ]
  })
}

# =============================================================================
# RESOURCE: SERVICE CONTROL POLICY - DENY PUBLIC S3
# =============================================================================
# Prevents any S3 bucket from becoming public.
# Why: Data exfiltration through public S3 buckets is a common attack vector.
# This SCP blocks the specific API calls that make buckets public.

resource "aws_organizations_policy" "deny_public_s3" {
  name        = "DenyPublicS3Access"
  description = "Prevents S3 buckets from being made public"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyPublicAcl"
        Effect = "Deny"
        Action = [
          "s3:PutBucketAcl",
          "s3:PutBucketPolicy",
          "s3:PutAccountPublicAccessBlock"
        ]
        Resource = "arn:aws:s3:::*"
        Condition = {
          # Block if it makes bucket public
          Or = [
            { Bool = { "s3:ExistingObjectTag/public" = "true" } },
            { Bool = { "s3:AccessControlList/Public" = "true" } }
          ]
        }
      }
    ]
  })
}

# =============================================================================
# RESOURCE: POLICY ATTACHMENTS
# =============================================================================
# Attach SCPs to OUs. Policies are inherited from parent OUs.
# Security Best Practice: Attach restrictive policies to the Root,
# then use allowlists in deeper OUs for more granular control.

resource "aws_organizations_policy_attachment" "security_ou" {
  target_id = aws_organizations_organizational_unit.security.id
  policy_id = aws_organizations_policy.deny_delete.id
}

resource "aws_organizations_policy_attachment" "workloads_ou_deny_delete" {
  target_id = aws_organizations_organizational_unit.workloads.id
  policy_id = aws_organizations_policy.deny_delete.id
}

resource "aws_organizations_policy_attachment" "workloads_ou_require_encryption" {
  target_id = aws_organizations_organizational_unit.workloads.id
  policy_id = aws_organizations_policy.require_encryption.id
}

resource "aws_organizations_policy_attachment" "workloads_ou_deny_public" {
  target_id = aws_organizations_organizational_unit.workloads.id
  policy_id = aws_organizations_policy.deny_public_s3.id
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "organization_id" {
  description = "AWS Organization ID"
  value       = aws_organizations_organization.this.id
}

output "organization_arn" {
  description = "AWS Organization ARN"
  value       = aws_organizations_organization.this.arn
}

output "organization_root_id" {
  description = "AWS Organization Root ID"
  value       = aws_organizations_organization.this.roots[0].id
}

output "security_ou_id" {
  description = "Security OU ID"
  value       = aws_organizations_organizational_unit.security.id
}

output "workloads_ou_id" {
  description = "Workloads OU ID"
  value       = aws_organizations_organizational_unit.workloads.id
}
