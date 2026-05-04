# =============================================================================
# AWS CONFIG MODULE - Compliance Monitoring
# =============================================================================
# AWS Config provides continuous monitoring and compliance checking.
#
# SECURITY BENEFITS:
# 1. CONFIGURATION HISTORY: Track all changes to resource configurations
# 2. COMPLIANCE RULES: Automated checks against security baselines
# 3. SECURITY ANALYSIS: Detect configurations that introduce risk
# 4. REMEDIATION: Automated fixing of non-compliant resources (with SSM)
#
# HOW IT WORKS:
# - Config Recorder: Captures all resource changes
# - Config Rules: Evaluates resources against desired states
# - Config Snapshot: Periodic state captures for comparison
# - Config History: All changes over time
#
# COMPLIANCE MAPPING:
# - CIS AWS Foundations Benchmark
# - PCI DSS
# - SOC 2
# - HIPAA

# =============================================================================
# DATA: AWS REGION
# =============================================================================

data "aws_region" "current" {}

# =============================================================================
# S3 BUCKET: AWS CONFIG
# =============================================================================
# AWS Config needs an S3 bucket to store configuration history.
# We reuse the log archive bucket, but in production,
# consider a dedicated bucket for better access control.

# =============================================================================
# SNS TOPIC: AWS CONFIG NOTIFICATIONS
# =============================================================================
# SNS topic for Config notifications.
# Use case: Real-time alerting when compliance rules are violated.

resource "aws_sns_topic" "config_notifications" {
  name = "${var.environment}-config-notifications"

  tags = {
    Name        = "${var.environment}-config-notifications"
    Description = "SNS topic for AWS Config notifications"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# DELIVERY CHANNEL
# =============================================================================
# Delivery channel specifies WHERE Config sends configuration data.
# - S3 bucket for configuration history
# - SNS topic for change notifications

resource "aws_config_delivery_channel" "main" {
  count = var.enable_aws_config ? 1 : 0

  name           = "${var.environment}-config-channel"
  s3_bucket_name = split("://", var.config_bucket_arn)[1]
  s3_key_prefix  = "aws-config/"

  # Frequency of configuration snapshots
  # Lower = more real-time = higher cost
  # 1 hour is good balance for most workloads
  # For PCI, consider 15 minutes
  snapshot_frequency = "One_Hour"

  # SNS topic for notifications
  sns_topic_arn = aws_sns_topic.config_notifications.arn

  tags = {
    Name        = "${var.environment}-config-channel"
    Description = "Delivery channel for AWS Config"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# CONFIG RECORDER
# =============================================================================
# Config Recorder must be started by someone with appropriate permissions.
# In our design, the security account manages Config in the workload account.

resource "aws_config_configuration_recorder" "main" {
  count = var.enable_aws_config ? 1 : 0

  name     = "${var.environment}-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  # What to record:
  # - All resource types (most comprehensive)
  # - OR specific resource types (lower cost)
  recording_group {
    # Record all supported resource types
    all_supported = true

    # Include global resources (IAM users, groups, roles)
    # These are global and not tied to a region
    include_global_resource_types = true

    # Exclude certain resource types (optional)
    # Exclude older resource types that generate noise
    # resource_types = []  # Empty = all supported
  }

  tags = {
    Name        = "${var.environment}-config-recorder"
    Description = "Configuration recorder for compliance monitoring"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# IAM ROLE: CONFIG RECORDER
# =============================================================================
# IAM role that AWS Config assumes to read resource configurations.

resource "aws_iam_role" "config_role" {
  name = "${var.environment}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowConfigService"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        # Condition: Config must be called from the correct account
        # This prevents other accounts from using this role
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.workload_account_id
          }
        }
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-config-role"
    Description = "IAM role for AWS Config recorder"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# POLICY: CONFIG RECORDER PERMISSIONS
# =============================================================================
# Permissions needed for Config to read resource configurations.

resource "aws_iam_policy" "config_recorder" {
  name = "${var.environment}-config-recorder-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadConfigurations"
        Effect = "Allow"
        # Config needs to describe/read configurations of all resources
        # This is a broad but necessary permission
        Action = [
          # EC2
          "ec2:Describe*",
          # S3
          "s3:GetBucket*",
          "s3:ListBucket*",
          "s3:PutBucketPublicAccessBlock",
          # IAM
          "iam:Get*",
          "iam:List*",
          # RDS
          "rds:Describe*",
          # Lambda
          "lambda:Get*",
          "lambda:List*",
          # VPC
          "ec2:DescribeVpc*",
          "ec2:DescribeSubnet*",
          "ec2:DescribeSecurityGroup*",
          "ec2:DescribeNetworkInterface*",
          # CloudTrail
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          # Config
          "config:Describe*",
          "config:Get*",
          "config:List*"
        ]
        Resource = "*"
        # Why "*"? Config must read all resource types
        # The role is already restricted by service and account
      },
      {
        Sid    = "WriteDelivery"
        Effect = "Allow"
        # Config needs to write to its S3 bucket
        Action = [
          "s3:PutObject",
          "s3:GetBucketPolicy"
        ]
        Resource = [
          "${var.config_bucket_arn}",
          "${var.config_bucket_arn}/*"
        ]
      },
      {
        Sid    = "SNSPublish"
        Effect = "Allow"
        # Config needs to publish to SNS for notifications
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.config_notifications.arn
      }
    ]
  })

  tags = {
    Name        = "${var.environment}-config-recorder-policy"
    Description = "Permissions for AWS Config recorder"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy_attachment" "config_recorder" {
  role       = aws_iam_role.config_role.name
  policy_arn = aws_iam_policy.config_recorder.arn
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "config_recorder_name" {
  description = "AWS Config recorder name"
  value       = var.enable_aws_config ? aws_config_configuration_recorder.main[0].name : null
}

output "sns_topic_arn" {
  description = "SNS topic ARN for Config notifications"
  value       = aws_sns_topic.config_notifications.arn
}
