"""
REST API Server for YAML Rule Builder
Deployable as a service for UI integration
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from api import RuleBuilderAPI
from models.rule import Rule
from models.field_selection import FieldSelection

app = Flask(__name__)
CORS(app)  # Enable CORS for UI

# Initialize API
api = RuleBuilderAPI()

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "yaml-rule-builder"})

@app.route('/api/v1/services', methods=['GET'])
def get_services():
    """Get list of available AWS services"""
    try:
        services = api.get_available_services()
        return jsonify({
            "success": True,
            "services": services,
            "count": len(services)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/v1/services/<service_name>/fields', methods=['GET'])
def get_fields(service_name: str):
    """Get available fields for a service"""
    try:
        fields = api.get_service_fields(service_name)
        return jsonify({
            "success": True,
            "service": service_name,
            "fields": fields,
            "count": len(fields)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/v1/rules/validate', methods=['POST'])
def validate_rule():
    """Validate a rule before generation"""
    try:
        data = request.get_json()
        
        # Create rule from input
        rule = api.create_rule_from_ui_input(data)
        
        # Validate
        validation = api.validate_rule(rule)
        
        return jsonify({
            "success": True,
            "validation": validation
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/v1/rules/generate', methods=['POST'])
def generate_rule():
    """Generate YAML and metadata for a rule"""
    try:
        data = request.get_json()
        
        # Create rule from input
        rule = api.create_rule_from_ui_input(data)
        
        # Validate first
        validation = api.validate_rule(rule)
        if not validation["valid"]:
            return jsonify({
                "success": False,
                "errors": validation["errors"],
                "warnings": validation["warnings"]
            }), 400
        
        # Generate
        result = api.generate_rule(rule)
        
        return jsonify({
            "success": result["success"],
            "yaml_path": result["yaml_path"],
            "metadata_path": result["metadata_path"],
            "existing_rules_found": result["existing_rules_found"],
            "errors": result.get("errors", []),
            "validation": validation
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/v1/rules/compare', methods=['POST'])
def compare_rule():
    """Check if a similar rule already exists"""
    try:
        data = request.get_json()
        
        # Create rule from input
        rule = api.create_rule_from_ui_input(data)
        
        # Validate to get existing rules
        validation = api.validate_rule(rule)
        
        return jsonify({
            "success": True,
            "existing_rules": validation["existing_rules"],
            "has_existing": len(validation["existing_rules"]) > 0
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({"success": False, "error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"success": False, "error": "Internal server error"}), 500

if __name__ == '__main__':
    # Run on all interfaces for Kubernetes
    app.run(host='0.0.0.0', port=5000, debug=False)

