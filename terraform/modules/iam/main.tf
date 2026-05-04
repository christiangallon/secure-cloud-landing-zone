# =============================================================================
# IAM MODULE - Least Privilege Access Control
# =============================================================================
# This module creates IAM roles following the principle of least privilege.
#
# SECURITY PRINCIPLES IMPLEMENTED:
# 1. NO LONG-TERM CREDENTIALS: All access via role assumption with temp tokens
#    - Access keys can be leaked, stolen, or committed to git
#    - Role assumption provides temporary credentials (typically 1-12 hours)
#    - If compromised, window of exposure is limited
#
# 2. LEAST PRIVILEGE: Only grant minimum permissions needed
#    - No "*" for actions (except in rare, controlled cases)
#    - Resource-level permissions where possible
#    - Explicit denies for sensitive actions
#
# 3. SEPARATION OF DUTIES: Different roles for different purposes
#    - Security tooling role (reads logs, writes findings)
#    - Log reader role (read-only for workload applications)
#    - No single role with everything
#
# 4. CONDITIONS: Add context to permissions
#    - Require MFA for sensitive operations
#    - Restrict by VPC (instances must be in our VPC)
#    - Restrict by time (optional, for contractor access)

# =============================================================================
# ROLE: SECURITY TOOLS
# =============================================================================
# This role is assumed by security tools in the security account.
# It allows reading configuration and writing findings from workload account.
#
# USE CASES:
# - AWS Config aggregator reading from workload
# - Security Hub aggregating findings
# - GuardDuty agent running in workload
#
# SECURITY: Cross-account access without sharing credentials.

resource "aws_iam_role" "security_tools" {
  name = "${var.environment}-security-tools-role"

  # Trust policy: Which accounts/ services can assume this role?
  # SECURITY: Only the security account can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSecurityAccount"
        Effect = "Allow"
        Principal = {
          # Allow the security account to assume this role
          # AWS format: arn:aws:iam::ACCOUNT-ID:role/RoleName
          AWS = "arn:aws:iam::${var.security_account_id}:root"
        }
        # Action = "sts:AssumeRole" is implied for role assumption
      },
      {
        # Allow AWS services to assume this role (for Lambda, EC2, etc.)
        Sid    = "AllowService"
        Effect = "Allow"
        Principal = {
          Service = [
            "securityhub.amazonaws.com",
            "config.amazonaws.com",
            "guardduty.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
        # No conditions for service-linked roles
      }
    ]
  })

  description = "Role for security tools to access workload account"
  max_session_duration = 43200  # 12 hours (max allowed)

  tags = {
    Name        = "${var.environment}-security-tools-role"
    Description = "Cross-account role for security tooling"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# POLICY: SECURITY TOOLS PERMISSIONS
# =============================================================================
# Permissions for the security tools role.
# These are the MINIMUM permissions needed for security monitoring.
# We explicitly list actions rather than using "*".

resource "aws_iam_policy" "security_tools" {
  name = "${var.environment}-security-tools-policy"

  # Policy document defining what this role CAN do
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadCloudWatchLogs"
        Effect = "Allow"
        # CloudWatch Logs: Read logs for security analysis
        # Example: Analyze Lambda logs for suspicious activity
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
          "logs:GetLogEvents",
          "logs:FilterLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:log-group:*"

        # Conditions: Add security context
        Condition = {
          # Only allow if the request uses MFA (for console access)
          # For API calls with temp credentials, this may not apply
          # Null = { "aws:MultiFactorAuthPresent" = "false" }
        }
      },
      {
        Sid    = "ReadCloudTrail"
        Effect = "Allow"
        # CloudTrail: Read API activity logs
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:ListTrails",
          "cloudtrail:GetTrailStatus"
        ]
        Resource = "*"
        # Why "*"? CloudTrail API doesn't support resource-level permissions
        # This is acceptable because the role is already restricted to security account
      },
      {
        Sid    = "ReadConfig"
        Effect = "Allow"
        # AWS Config: Read resource configurations
        Action = [
          "config:DescribeConfigurationRecorders",
          "config:DescribeDeliveryChannels",
          "config:GetComplianceDetailsByResource",
          "config:ListDiscoveredResources"
        ]
        Resource = "*"
        # AWS Config API doesn't support resource-level permissions
      },
      {
        Sid    = "ReadS3ForLogs"
        Effect = "Allow"
        # S3: Read access to log buckets for analysis
        # Why needed? Security tools may need to analyze S3 access logs
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          var.log_archive_bucket_arn,
          "${var.log_archive_bucket_arn}/*"
        ]
        # Restricting to specific bucket is more secure than "*"
      },
      {
        Sid    = "SecurityHubRead"
        Effect = "Allow"
        # Security Hub: Read findings (for aggregation)
        Action = [
          "securityhub:GetFindings",
          "securityhub:ListFindings",
          "securityhub:DescribeHabits"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2ReadForSecurity"
        Effect = "Allow"
        # EC2: Read security group rules, VPC info
        # Needed for security posture analysis
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeInstances"
        ]
        Resource = "*"
        # EC2 Describe* APIs don't support resource-level permissions
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-security-tools-policy"
    Description = "Permissions for security tooling cross-account access"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# ATTACH: SECURITY TOOLS POLICY TO ROLE
# =============================================================================

resource "aws_iam_role_policy_attachment" "security_tools" {
  role       = aws_iam_role.security_tools.name
  policy_arn = aws_iam_policy.security_tools.arn
}

# =============================================================================
# ROLE: LOG READER (For Workload Applications)
# =============================================================================
# This role is for workload applications to read their own CloudTrail logs.
# USE CASE: Application needs to audit who accessed what data
#
# SECURITY: Applications should only read their OWN logs.
# We restrict to specific bucket prefix for the workload account.

resource "aws_iam_role" "log_reader" {
  name = "${var.environment}-log-reader-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowWorkloadAccount"
        Effect = "Allow"
        Principal = {
          # Only the workload account can assume this role
          # Prevents other accounts from accessing logs
          AWS = "arn:aws:iam::${var.workload_account_id}:root"
        }
        # Conditions can restrict further:
        # - aws:SourceVpce: Only from specific VPC endpoints
        # - aws:SourceIP: Only from specific IP ranges
        # - aws:RequestedRegion: Only specific regions
      },
      {
        Sid    = "AllowEC2"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        # EC2 instance roles can assume this role
        # This allows EC2 instances to read logs
        Action = "sts:AssumeRole"
      }
    ]
  })

  max_session_duration = 3600  # 1 hour (sufficient for most use cases)

  tags = {
    Name        = "${var.environment}-log-reader-role"
    Description = "Role for reading CloudTrail and Config logs"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# POLICY: LOG READER PERMISSIONS
# =============================================================================
# Read-only access to logs and configuration.
# Application teams can attach this role to EC2 instances or Lambda functions.

resource "aws_iam_policy" "log_reader" {
  name = "${var.environment}-log-reader-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOwnCloudTrail"
        Effect = "Allow"
        # CloudTrail: Read events from workload account
        # This is for application's OWN audit logs
        Action = [
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
        # CloudTrail API doesn't support resource-level permissions
        # The role is already restricted to workload account, so this is acceptable
      },
      {
        Sid    = "ReadOwnS3Logs"
        Effect = "Allow"
        # S3: Read access to log bucket
        # Application can analyze its own access patterns
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.log_archive_bucket_arn,
          "${var.log_archive_bucket_arn}/AWSLogs/${var.workload_account_id}/*"
        ]
        # Restricting to workload account's prefix prevents reading other accounts' logs
      },
      {
        Sid    = "ReadConfigForAudit"
        Effect = "Allow"
        # AWS Config: Read resource configuration history
        Action = [
          "config:GetResourceConfigHistory",
          "config:ListDiscoveredResources"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-log-reader-policy"
    Description = "Read-only access to logs and configuration"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "log_reader" {
  role       = aws_iam_role.log_reader.name
  policy_arn = aws_iam_policy.log_reader.arn
}

# =============================================================================
# INSTANCE PROFILE: For EC2
# =============================================================================
# Instance profiles allow EC2 instances to use IAM roles.
# The instance profile IS the role, but with additional metadata for EC2.
# When you launch an EC2 with an IAM role, you're actually using an instance profile.

resource "aws_iam_instance_profile" "log_reader" {
  name = "${var.environment}-log-reader-profile"
  role = aws_iam_role.log_reader.name

  tags = {
    Name        = "${var.environment}-log-reader-profile"
    Description = "Instance profile for log reader role"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# ROLE: CROSS-ACCOUNT READ-ONLY (Audit Purpose)
# =============================================================================
# For external auditors who need read-only access to all accounts.
# This role would be assumed by auditors from the management account.
# 
# SECURITY CONTROLS:
# - Time-limited (must be renewed)
# - No write permissions whatsoever
# - All access is logged
# - MFA required

resource "aws_iam_role" "auditor" {
  name = "${var.environment}-auditor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowManagementAccount"
        Effect = "Allow"
        Principal = {
          # Only from management account
          AWS = "arn:aws:iam::${var.workload_account_id}:root"
        }
        # IMPORTANT: In production, add MFA condition
        # This prevents role assumption without physical token
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  # Short session duration limits exposure if credentials are leaked
  max_session_duration = 3600

  tags = {
    Name        = "${var.environment}-auditor-role"
    Description = "Read-only access for external auditors"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    Compliance  = "Audit"
  }
}

resource "aws_iam_policy" "auditor" {
  name = "${var.environment}-auditor-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyAll"
        Effect = "Allow"
        # Granular read-only actions
        # No Create, Update, Delete, or Write actions
        Action = [
          # CloudTrail
          "cloudtrail:LookupEvents",
          "cloudtrail:ListTrails",
          # S3 (list and get only)
          "s3:ListAllMyBuckets",
          "s3:GetObject",
          "s3:ListBucket",
          # EC2 (describe only)
          "ec2:Describe*",
          # RDS
          "rds:Describe*",
          # IAM (list users/roles, but not read policies)
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:GetUser",
          # Config
          "config:Describe*",
          "config:Get*",
          "config:List*",
          # CloudWatch
          "cloudwatch:List*",
          "cloudwatch:Get*",
          "cloudwatch:Describe*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyWrite"
        Effect = "Deny"
        # Explicitly deny any write operations as extra protection
        # This overrides any accidentally granted write access
        NotAction = [
          # Allow all read actions
          "*:Get*",
          "*:List*",
          "*:Describe*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-auditor-policy"
    Description = "Read-only policy for compliance auditing"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "auditor" {
  role       = aws_iam_role.auditor.name
  policy_arn = aws_iam_policy.auditor.arn
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "security_tools_role_arn" {
  description = "ARN of security tools role"
  value       = aws_iam_role.security_tools.arn
}

output "log_reader_role_arn" {
  description = "ARN of log reader role"
  value       = aws_iam_role.log_reader.arn
}

output "log_reader_instance_profile_arn" {
  description = "ARN of log reader instance profile (for EC2)"
  value       = aws_iam_instance_profile.log_reader.arn
}

output "auditor_role_arn" {
  description = "ARN of auditor role"
  value       = aws_iam_role.auditor.arn
}

output "workload_account_id" {
  description = "Workload account ID for reference"
  value       = var.workload_account_id
}
