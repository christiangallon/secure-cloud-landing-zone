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
