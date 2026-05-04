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
