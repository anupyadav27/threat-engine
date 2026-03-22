provider "google" {
  project = "my-test-project"
  region  = "us-central1"
}

# ❌ Noncompliant: Versioning explicitly disabled
resource "google_storage_bucket" "bad_example_explicit" {
  name     = "bucket-without-versioning-explicit"
  location = "US"

  versioning {
    enabled = false
  }
}

# ❌ Noncompliant: Versioning block missing entirely
resource "google_storage_bucket" "bad_example_missing" {
  name     = "bucket-without-versioning-missing"
  location = "US"
}

# ✅ Compliant: Versioning enabled
resource "google_storage_bucket" "good_example" {
  name     = "bucket-with-versioning"
  location = "US"

  versioning {
    enabled = true
  }
}
