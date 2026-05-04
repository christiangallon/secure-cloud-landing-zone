output "config_recorder_name" {
  description = "AWS Config recorder name"
  value       = var.enable_aws_config ? aws_config_configuration_recorder.main[0].name : null
}

output "sns_topic_arn" {
  description = "SNS topic ARN for Config notifications"
  value       = aws_sns_topic.config_notifications.arn
}
