from rest_framework import serializers
from .models import Threat, ThreatRemediationStep, ThreatRelatedFinding

class ThreatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Threat
        fields = [
            "id", "tenant_id", "name", "severity", "status",
            "description", "created_at", "updated_at"
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

class ThreatRemediationStepSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatRemediationStep
        fields = [
            "id", "threat_id", "step_order", "step_description",
            "created_at", "updated_at"
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

class ThreatRelatedFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatRelatedFinding
        fields = [
            "id", "threat_id", "finding_id", "created_at", "updated_at"
        ]
        read_only_fields = ["id", "created_at", "updated_at"]