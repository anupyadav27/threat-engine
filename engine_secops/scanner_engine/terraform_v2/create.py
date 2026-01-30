import os
import json

folder = "terraform_docs1"
files = [f for f in os.listdir(folder) if f.endswith(".json")][:52]

def infer_logic(data):
    title = data.get("title", "").lower()
    examples = data.get("examples", {})
    # Use existing logic if present and not a placeholder
    logic = data.get("logic", {})
    if logic and logic.get("resource_type", "").startswith("<") is False:
        return logic

    # Example inference rules (expand as needed)
    if "s3 bucket" in title and "versioning" in title:
        return {
            "resource_type": "aws_s3_bucket",
            "property_path": ["versioning", "enabled"],
            "check_type": "not_exists",
            "forbidden_values": [],
            "required_values": [True],
            "custom_function": ""
        }
    if "sqs" in title:
        return {
            "resource_type": "aws_sqs_queue",
            "property_path": ["kms_master_key_id"],
            "check_type": "not_exists",
            "forbidden_values": [],
            "required_values": [],
            "custom_function": ""
        }
    if "sns" in title:
        return {
            "resource_type": "aws_sns_topic",
            "property_path": ["kms_master_key_id"],
            "check_type": "not_exists",
            "forbidden_values": [],
            "required_values": [],
            "custom_function": ""
        }
    if "rds" in title:
        return {
            "resource_type": "aws_db_instance",
            "property_path": ["storage_encrypted"],
            "check_type": "equals",
            "forbidden_values": [False],
            "required_values": [True],
            "custom_function": ""
        }
    if "efs" in title:
        return {
            "resource_type": "aws_efs_file_system",
            "property_path": ["encrypted"],
            "check_type": "equals",
            "forbidden_values": [False],
            "required_values": [True],
            "custom_function": ""
        }
    if "elasticsearch" in title:
        return {
            "resource_type": "aws_elasticsearch_domain",
            "property_path": ["encrypt_at_rest", "enabled"],
            "check_type": "equals",
            "forbidden_values": [False],
            "required_values": [True],
            "custom_function": ""
        }
    if "ebs" in title:
        return {
            "resource_type": "aws_ebs_volume",
            "property_path": ["encrypted"],
            "check_type": "equals",
            "forbidden_values": [False],
            "required_values": [True],
            "custom_function": ""
        }
    # Add more rules as needed for your environment

    # Default placeholder if nothing matches
    return {
        "resource_type": "<TO_BE_FILLED>",
        "property_path": ["<TO_BE_FILLED>"],
        "check_type": "<TO_BE_FILLED>",
        "forbidden_values": [],
        "required_values": [],
        "custom_function": ""
    }

for filename in files:
    path = os.path.join(folder, filename)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    data["logic"] = infer_logic(data)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    # print(f"Updated logic for {filename}")

# print("Done updating logic for 52 files.")