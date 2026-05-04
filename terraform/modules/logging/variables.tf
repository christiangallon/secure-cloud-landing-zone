variable "environment" {
  description = "Environment name"
  type        = string
}

variable "management_account_id" {
  description = "Management account ID"
  type        = string
}

variable "security_account_id" {
  description = "Security account ID"
  type        = string
}

variable "workload_account_id" {
  description = "Workload account ID"
  type        = string
}

variable "cloudtrail_s3_bucket_arn" {
  description = "S3 bucket ARN for CloudTrail logs"
  type        = string
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain CloudTrail logs"
  type        = number
  default     = 30
}

variable "is_multi_region_trail" {
  description = "Enable multi-region CloudTrail trail"
  type        = bool
  default     = true
}

variable "enable_log_file_validation" {
  description = "Enable CloudTrail log file validation"
  type        = bool
  default     = true
}
