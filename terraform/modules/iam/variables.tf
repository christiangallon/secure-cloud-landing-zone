variable "environment" {
  description = "Environment name"
  type        = string
}

variable "log_archive_bucket_arn" {
  description = "ARN of the log archive S3 bucket"
  type        = string
}

variable "workload_account_id" {
  description = "Workload account ID"
  type        = string
}

variable "security_account_id" {
  description = "Security account ID"
  type        = string
}

variable "allowed_vpc_id" {
  description = "VPC ID to restrict instance role access (optional)"
  type        = string
  default     = ""
}
