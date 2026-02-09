# threats_management/models.py
# DEPRECATED: These models are being replaced by enriched models in models_enriched.py
# Migration path: Use ThreatEngineClient from utils.engine_clients
# Old: Threat.objects.filter(tenant_id=tenant_id)
# New: ThreatEngineClient().get_threats(tenant_id=tenant_id)
import uuid
from django.db import models
from tenant_management.models import Tenants

# DEPRECATED: Use Threat model from models_enriched.py or ThreatEngineClient
class Threat(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenants,
        on_delete=models.CASCADE,
        related_name="threats"
    )
    name = models.TextField()
    severity = models.TextField(blank=True, null=True)
    status = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'threats'
        indexes = [
            models.Index(fields=['tenant', 'severity']),
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['name']),
        ]

    def __str__(self):
        return f"{self.name} ({self.severity})"


# DEPRECATED: ThreatRemediationStep - Remediation is now in Threat.remediation (JSON)
# Migration path: Use Threat.remediation field from enriched model or API
class ThreatRemediationStep(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    threat = models.ForeignKey(
        Threat,
        on_delete=models.CASCADE,
        related_name="remediation_steps"
    )
    step_order = models.IntegerField(blank=True, null=True)
    step_description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'threat_remediation_steps'
        indexes = [
            models.Index(fields=['threat', 'step_order']),
        ]

    def __str__(self):
        return f"Step {self.step_order} for {self.threat.name}"


# DEPRECATED: ThreatRelatedFinding - Findings are now in Threat.misconfig_finding_refs (array)
# Migration path: Use Threat.misconfig_finding_refs from enriched model or API
class ThreatRelatedFinding(models.Model):
    id = models.TextField(primary_key=True, default=uuid.uuid4, editable=False)
    threat = models.ForeignKey(
        Threat,
        on_delete=models.CASCADE,
        related_name="related_findings"
    )
    finding_id = models.TextField()  # External finding ID (e.g., from scans/vulnerabilities)
    created_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = 'threat_related_findings'
        indexes = [
            models.Index(fields=['threat']),
            models.Index(fields=['finding_id']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['threat', 'finding_id'],
                name='unique_threat_finding'
            )
        ]

    def __str__(self):
        return f"Threat {self.threat.name} → Finding {self.finding_id}"