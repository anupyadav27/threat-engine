# Test file to trigger multiple Terraform security rules

resource "aws_s3_bucket" "bad_bucket" {
  bucket = "my-bad-bucket"
  acl    = "private"
  # No logging block (should trigger logging rule)
  versioning {
    enabled    = true
    mfa_delete = false # Should trigger MFA delete rule
  }
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "public-bucket"
  acl    = "public-read" # Should trigger public ACL rule
  versioning {
    enabled    = true
    mfa_delete = true
  }
}

resource "aws_db_instance" "unencrypted_db" {
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "foo"
  password             = "foobarbaz"
  parameter_group_name = "default.mysql5.7"
  # No storage_encrypted = true (should trigger RDS encryption rule)
}

resource "aws_security_group" "open_sg" {
  name        = "open-sg"
  description = "Open to the world"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Should trigger open security group rule
  }
}
