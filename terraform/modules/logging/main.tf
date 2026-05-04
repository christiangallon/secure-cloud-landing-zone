# =============================================================================
# LOGGING MODULE - CloudTrail Configuration
# =============================================================================
# This module configures CloudTrail for comprehensive API activity logging.
#
# CLOUDTRAIL SECURITY BENEFITS:
# 1. AUDIT TRAIL: Every API call is logged with:
#    - Who made the call (IAM user/role)
#    - When (timestamp)
#    - From where (source IP)
#    - What was requested (API action, parameters)
#    - What was the result (response)
#
# 2. COMPLIANCE: Satisfies requirements for:
#    - SOC 2: Activity monitoring
#    - PCI DSS: Audit logging
#    - HIPAA: Access logging
#    - ISO 27001: Information security
#
# 3. SECURITY MONITORING: Can detect:
#    - Brute force attacks
#    - Privilege escalation
#    - Data exfiltration
#    - Configuration changes
#
# 4. FORENSICS: After a breach, CloudTrail logs are critical for:
#    - Understanding what happened
#    - Identifying the timeline
#    - Finding the source
#    - Gathering evidence

# =============================================================================
# DATA: AWS PARTITION
# =============================================================================
# Some AWS services have different ARNs per partition (AWS, AWS GovCloud, etc.)
# This data source gets the current partition for correct ARN construction.

data "aws_partition" "current" {}

# =============================================================================
# CLOUDTRAIL: MULTI-REGION TRAIL
# =============================================================================
# CloudTrail records events from ALL AWS regions, even if you're in one region.
# Why multi-region?
# 1. Threats can come from ANY region - attackers often use less-monitored ones
# 2. Some services only exist in specific regions
# 3. Forensics requires seeing the "big picture"
# 4. Compliance may require global visibility

resource "aws_cloudtrail" "main" {
  # Only create if feature flag is enabled
  count = var.enable_cloudtrail ? 1 : 0

  name               = "${var.environment}-cloudtrail"
  s3_bucket_name     = split("://", var.cloudtrail_s3_bucket_arn)[1]  # Extract bucket name
  s3_key_prefix      = "cloudtrail/"  # Prefix for organization in bucket
  is_multi_region_trail = true  # CRITICAL: Log from ALL regions

  # Include management events (CreateRole, DeleteUser, etc.)
  # These are different from data events (S3 GET, DynamoDB Query)
  include_management_events = true

  # Read/Write events:
  # - Read: API calls that don't modify resources (List, Describe, Get)
  # - Write: API calls that modify resources (Create, Delete, Update)
  # We log BOTH for complete visibility
  read_write_type           = "All"

  # Enable log file validation
  # CloudTrail creates a digest file for each log file
  # You can verify log integrity using AWS CLI
  # Why? Detects if someone tampered with logs after the fact
  enable_log_file_validation = true

  # Encrypt logs with SSE-S3 (AWS-managed keys)
  # Additional security: Could use SSE-KMS for customer-managed keys
  enable_logging = true

  # SNS notification for log delivery (optional)
  # Useful for real-time security monitoring
  # sns_topic_name = aws_sns_topic.cloudtrail.arn

  tags = {
    Name        = "${var.environment}-cloudtrail"
    Description = "Multi-region CloudTrail for audit logging"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
  }
}

# =============================================================================
# CLOUDTRAIL: LOG TAGS
# =============================================================================
# Tags on CloudTrail help with cost allocation and filtering.
# You can filter CloudTrail events by tags in CloudWatch Insights.

resource "aws_cloudtrail" "log_tags" {
  count = var.enable_cloudtrail ? 1 : 0

  name               = "${var.environment}-cloudtrail"
  s3_bucket_name     = split("://", var.cloudtrail_s3_bucket_arn)[1]
  is_multi_region_trail = true
  enable_log_file_validation = true
  include_management_events = true
  read_write_type           = "All"

  tags = {
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    Compliance  = "SOC2,PCI-DSS,ISO27001"
  }
}

# =============================================================================
# CLOUDTRAIL: ORGANIZATION TRAIL
# =============================================================================
# An organization trail logs events for ALL accounts in the organization.
# This is the ENTERPRISE approach - one trail, everywhere.
#
# Prerequisites:
# - Must be logged in as the management account
# - Organization must have all features enabled
#
# Benefits:
# - Single point of configuration
# - Consistent logging across all accounts
# - Lower cost (one trail vs. many)

resource "aws_cloudtrail" "organization" {
  count = var.enable_cloudtrail ? 1 : 0

  name               = "${var.environment}-org-cloudtrail"
  s3_bucket_name     = split("://", var.cloudtrail_s3_bucket_arn)[1]
  is_organization_trail = true  # This trail applies to ALL accounts in org
  is_multi_region_trail = true
  enable_log_file_validation = true
  include_management_events = true
  read_write_type           = "All"

  # The management account ID is used for the trail's IAM role
  # This role is created automatically by CloudTrail
  # but we need to specify it for organization trails
  # sns_topic_name = aws_sns_topic.cloudtrail.arn

  tags = {
    Name        = "${var.environment}-org-cloudtrail"
    Description = "Organization-wide CloudTrail"
    Project     = "SecureCloudLandingZone"
    Environment = var.environment
    Type        = "Organization"
  }
}

# =============================================================================
# CLOUDTRAIL: EVENT SELECTOR (Advanced)
# =============================================================================
# Event selectors provide fine-grained control over what's logged.
# Use for:
# 1. Reducing costs by excluding noisy data events
# 2. Focusing on specific S3 buckets for data events
# 3. Logging Lambda function invocations only for specific functions
#
# Default: Logs all management events + all data events from S3 and Lambda
# For most use cases, the default is fine.

resource "aws_cloudtrail_event_selector" "workload" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${var.environment}-cloudtrail"
  trail_name     = aws_cloudtrail.main[0].name
  register       = true  # Enable event selector

  # Management events are always logged (cannot exclude)
  # This selector adds DATA events (S3, Lambda)

  event_selector {
    # Data event source: S3
    # Logs S3 object-level operations (GetObject, PutObject, DeleteObject)
    # These are high-volume but valuable for security
    read_write_type = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      # ARN of the bucket to log
      # Warning: Each object access creates a log entry
      # For high-traffic buckets, this can be expensive
      values = ["${var.cloudtrail_s3_bucket_arn}/*"]
    }
  }
}

# =============================================================================
# CLOUDTRAIL: SNS TOPIC (Optional)
# =============================================================================
# SNS topic for CloudTrail log delivery notifications.
# Use case: Real-time alerting when specific events occur
#
# Example integration:
# - Lambda function triggered by SNS
# - Lambda analyzes the event
# - If suspicious (e.g., DeleteSecurityGroup from unknown IP), alert
#
# This is commented out to reduce complexity.
# Uncomment if you need real-time security alerting.

# resource "aws_sns_topic" "cloudtrail" {
#   name = "${var.environment}-cloudtrail-alerts"
#
#   tags = {
#     Project = "SecureCloudLandingZone"
#   }
# }
#
# resource "aws_sns_topic_subscription" "cloudtrail_alerts" {
#   topic_arn = aws_sns_topic.cloudtrail.arn
#   protocol  = "lambda"
#   endpoint  = aws_lambda_function.alert.arn
# }

# =============================================================================
# OUTPUTS
# =============================================================================

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = var.enable_cloudtrail ? aws_cloudtrail.main[0].arn : null
}

output "cloudtrail_name" {
  description = "CloudTrail name"
  value       = var.enable_cloudtrail ? aws_cloudtrail.main[0].name : null
}

output "log_archive_bucket_name" {
  description = "Log archive S3 bucket name"
  value       = split("://", var.cloudtrail_s3_bucket_arn)[1]
}

output "log_archive_bucket_arn" {
  description = "Log archive S3 bucket ARN"
  value       = var.cloudtrail_s3_bucket_arn
}
