variable "environment" {
  description = "Environment name"
  type        = string
}

variable "workload_account_id" {
  description = "Workload account ID"
  type        = string
}

variable "workload_vpc_id" {
  description = "VPC ID for Config recording"
  type        = string
}

variable "config_bucket_arn" {
  description = "S3 bucket ARN for Config data"
  type        = string
}

variable "enable_aws_config" {
  description = "Enable AWS Config"
  type        = bool
  default     = true
}
