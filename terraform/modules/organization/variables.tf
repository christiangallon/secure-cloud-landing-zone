variable "management_account_id" {
  description = "AWS Management Account ID"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "security_account_email" {
  description = "Email for security account (must be unique in AWS)"
  type        = string
}

variable "security_account_name" {
  description = "Name for security account"
  type        = string
}

variable "workload_account_email" {
  description = "Email for workload account (must be unique in AWS)"
  type        = string
}

variable "workload_account_name" {
  description = "Name for workload account"
  type        = string
}
