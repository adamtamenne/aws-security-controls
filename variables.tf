variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "org_name" {
  description = "Name prefix for the organization resources"
  type        = string
  default     = "security-lab"
}

variable "approved_regions" {
  description = "AWS regions where resource creation is allowed"
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}
