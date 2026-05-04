variable "environment" {
  description = "Environment name"
  type        = string
}

variable "log_archive_bucket_name" {
  description = "S3 bucket name for log archive"
  type        = string
}

variable "workload_bucket_name" {
  description = "S3 bucket name for workload data"
  type        = string
}

variable "log_archive_bucket_account_id" {
  description = "Account ID for log archive bucket cross-account access"
  type        = string
}

variable "allowed_admin_cidrs" {
  description = "CIDR blocks allowed for administrative SSH/RDP access"
  type        = list(string)
  default     = []
}

variable "allowed_http_cidrs" {
  description = "CIDR blocks allowed for HTTP/HTTPS traffic"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "vpc_id" {
  description = "VPC ID for security group creation"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for RDS placement"
  type        = list(string)
}

variable "enable_mfa_delete" {
  description = "Enable MFA delete on S3 buckets"
  type        = bool
  default     = false
}

variable "lifecycle_rule_enabled" {
  description = "Enable S3 lifecycle rules"
  type        = bool
  default     = true
}
