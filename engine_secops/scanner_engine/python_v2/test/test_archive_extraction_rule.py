import zipfile
import os

def extract_archive_uncontrolled(archive_path, extract_to):
    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
        # This will trigger the rule: extractall without resource control
        zip_ref.extractall(extract_to)

if __name__ == "__main__":
    # Create a dummy zip file for testing
    test_zip = "test_archive.zip"
    test_dir = "extracted_files"
    with zipfile.ZipFile(test_zip, 'w') as zipf:
        zipf.writestr("dummy.txt", "This is a test.")
    os.makedirs(test_dir, exist_ok=True)
    extract_archive_uncontrolled(test_zip, test_dir)
    print(f"Extracted to {test_dir}")
