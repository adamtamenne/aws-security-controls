variable "approved_regions" {
  description = "List of AWS regions where resource creation is allowed"
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}
