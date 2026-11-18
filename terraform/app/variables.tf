variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "project" {
  type    = string
  default = "phishing-detector"
}

variable "instance_type" {
  description = "t3.micro: 2 vCPU, 1 GB RAM."
  type        = string
  default     = "t3.micro"
}

variable "asg_min" {
  description = "Two instances, one per AZ - survives losing an instance or an AZ."
  type        = number
  default     = 2
}

variable "asg_desired" {
  type    = number
  default = 2
}

variable "asg_max" {
  description = "Upper limit for CPU-based scaling (keeps cost bounded)."
  type        = number
  default     = 4
}

variable "alert_email" {
  description = "Where alarm emails go. Set it in terraform.tfvars (git-ignored) - see example.tfvars. Empty = no email subscription."
  type        = string
  default     = ""

  validation {
    condition     = var.alert_email == "" || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be an email address or empty."
  }
}
