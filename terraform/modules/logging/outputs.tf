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
