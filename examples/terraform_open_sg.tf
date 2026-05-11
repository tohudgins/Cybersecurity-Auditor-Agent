// Deliberately weak Terraform for demo purposes.
// Triggers: 0.0.0.0/0 ingress on SSH, public-read S3 ACL, unencrypted RDS.

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web server security group"
  vpc_id      = "vpc-1234567"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "uploads" {
  bucket = "acme-public-uploads"
  acl    = "public-read"
}

resource "aws_db_instance" "primary" {
  identifier        = "acme-db"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  username = "admin"
  password = "changeme123"

  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
