# =============================================================================
# OUTPUTS - Important values to capture after deployment
# =============================================================================
# These outputs are useful for:
# 1. Integration with other Terraform configurations
# 2. CI/CD pipeline configuration
# 3. Manual verification and testing

output "organization_info" {
  description = "AWS Organization information"
  value = {
    id      = module.organization.organization_id
    arn     = module.organization.organization_arn
    root_id = module.organization.organization_root_id
  }
}

output "security_account_info" {
  description = "Security account information"
  value = {
    id      = data.aws_caller_identity.security.account_id
    arn     = data.aws_caller_identity.security.arn
    region  = var.aws_region
  }
}

output "workload_account_info" {
  description = "Workload account information"
  value = {
    id      = data.aws_caller_identity.workload.account_id
    arn     = data.aws_caller_identity.workload.arn
    region  = var.aws_region
  }
}

output "vpc_info" {
  description = "VPC configuration information"
  value = {
    id                        = module.network.vpc_id
    cidr_block                = module.network.vpc_cidr
    public_subnet_ids         = module.network.public_subnet_ids
    private_subnet_ids        = module.network.private_subnet_ids
    nat_gateway_ip            = module.network.nat_gateway_ip
    availability_zones        = var.availability_zones
  }
}

output "security_groups" {
  description = "Security group IDs"
  value = {
    # The web security group allows HTTP/HTTPS from the ALB only
    web_sg_id         = module.security.web_security_group_id
    # The app security group allows traffic only from web SG
    app_sg_id         = module.security.app_security_group_id
    # The database security group allows traffic only from app SG
    database_sg_id    = module.security.database_security_group_id
  }
}

output "s3_buckets" {
  description = "S3 bucket information"
  value = {
    log_archive = {
      name = module.logging.log_archive_bucket_name
      arn  = module.logging.log_archive_bucket_arn
    }
    workload = {
      name = module.security.workload_bucket_name
      arn  = module.security.workload_bucket_arn
    }
  }
}

output "cloudtrail_info" {
  description = "CloudTrail configuration"
  value = {
    arn                    = module.logging.cloudtrail_arn
    s3_bucket_name         = module.logging.log_archive_bucket_name
    multi_region_enabled   = var.enable_cloudtrail
  }
}

output "iam_roles" {
  description = "Important IAM role ARNs for cross-account access"
  value = {
    # Role that workloads can assume to read logs
    log_reader_role_arn = module.iam.log_reader_role_arn
    # Role that security tools can assume
    security_tools_role_arn = module.iam.security_tools_role_arn
  }
}

output "deployment_commands" {
  description = "Commands to verify deployment"
  value = {
    # List CloudTrail trails
    list_trails      = "aws cloudtrail list-trails --profile workload"
    # List S3 buckets
    list_buckets     = "aws s3 ls --profile workload"
    # Get VPC info
    describe_vpc     = "aws ec2 describe-vpcs --vpc-ids ${module.network.vpc_id} --profile workload"
    # Get AWS Config rules
    config_rules     = "aws configservice describe-config-rules --profile security"
  }
}

output "next_steps" {
  description = "Recommended next steps after deployment"
  value = {
    "1_enable_security_hub"    = "aws securityhub enable-security-hub --region ${var.aws_region} --profile security"
    "2_enable_guardduty"       = "aws guardduty enable-organization --region ${var.aws_region} --profile security"
    "3_setup_waf"              = "Create Web ACL in AWS WAF for ALB protection"
    "4_configure_backup"       = "Set up AWS Backup for RDS and EC2"
    "5_review_iam"             = "Review all IAM policies in IAM Access Analyzer"
  }
}
