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
  type    = number
  default = 1
}

variable "asg_desired" {
  type    = number
  default = 1
}

variable "asg_max" {
  type    = number
  default = 2
}
