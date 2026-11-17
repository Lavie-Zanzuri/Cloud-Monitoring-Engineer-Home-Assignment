# ------------------------------------------------------------------------------
# What the instances may do in AWS - and nothing more (least privilege).
# The role gives them short-lived credentials that rotate automatically;
# no access keys ever live on the servers.
# ------------------------------------------------------------------------------

resource "aws_iam_role" "app" {
  name = "${var.project}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Session Manager shell access (replaces SSH and port 22).
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# CloudWatch agent: ship logs and memory/disk metrics.
resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Only the app package, and only the DB secret.
resource "aws_iam_role_policy" "app" {
  name = "${var.project}-app-access"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadAppPackage"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.artifacts.arn}/releases/*"
      },
      {
        Sid      = "ReadDbSecret"
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = local.f.db_master_secret_arn
      },
    ]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.project}-app-profile"
  role = aws_iam_role.app.name
}
