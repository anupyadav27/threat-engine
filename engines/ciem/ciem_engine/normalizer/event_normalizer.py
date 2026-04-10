"""
Event Normalizer — 6-step pipeline to convert raw logs to OCSF schema.

Step 1: Parse source-specific format (JSON, CSV, etc.)
Step 2: Map to OCSF/normalized schema fields
Step 3: Flatten nested structures
Step 4: Type conversion (timestamp, IP, int)
Step 5: Add source metadata (bucket, key, region)
Step 6: Initial enrichment (geoIP, asset lookup from inventory)
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .schema import (
    NormalizedEvent, Actor, Resource, NetworkInfo, HttpInfo,
    EventCategory, EventOutcome,
)

logger = logging.getLogger(__name__)


class EventNormalizer:
    """6-step normalization pipeline for raw log events."""

    def __init__(
        self,
        source_type: str,
        field_mapping: Dict[str, str],
        category: str = EventCategory.API_ACTIVITY,
        scan_run_id: str = "",
        tenant_id: str = "",
        source_bucket: str = "",
        source_region: str = "",
        asset_index: Optional[Dict[str, Dict]] = None,
        identifier_index: Optional[Dict[str, Dict]] = None,
    ):
        """
        Args:
            source_type: Log source (cloudtrail, vpc_flow, s3_access, alb, waf, dns)
            field_mapping: Maps source field paths → NormalizedEvent fields
            category: Default event category
            scan_run_id: Pipeline scan ID
            tenant_id: Tenant
            source_bucket: S3 bucket where logs were read from
            source_region: Region of the log source
            asset_index: Dict of resource_uid → asset dict from inventory (for enrichment)
            identifier_index: Dict of service.resource_type → {identifier_pattern, primary_param}
                              from resource_inventory_identifier table
        """
        self.source_type = source_type
        self.field_mapping = field_mapping
        self.category = category
        self.scan_run_id = scan_run_id
        self.tenant_id = tenant_id
        self.source_bucket = source_bucket
        self.source_region = source_region
        self.asset_index = asset_index or {}
        self.identifier_index = identifier_index or {}  # service.type → {pattern, primary_param}

    def normalize(self, raw_event: Dict[str, Any], source_key: str = "") -> Optional[NormalizedEvent]:
        """Run the 6-step normalization pipeline on a single event.

        Returns NormalizedEvent or None if event should be skipped.
        """
        try:
            # Step 1: Parse (already parsed — raw_event is a dict)
            # Step 2: Map to schema
            event = self._step2_map_fields(raw_event)
            # Step 3: Flatten nested structures
            self._step3_flatten(event, raw_event)
            # Step 4: Type conversion
            self._step4_type_convert(event, raw_event)
            # Step 5: Add source metadata
            self._step5_source_metadata(event, source_key)
            # Step 6: Enrichment
            self._step6_enrich(event)
            return event
        except Exception as exc:
            logger.debug(f"Normalization failed for {self.source_type} event: {exc}")
            return None

    def normalize_batch(self, raw_events: List[Dict], source_key: str = "") -> List[NormalizedEvent]:
        """Normalize a batch of raw events."""
        results = []
        for raw in raw_events:
            event = self.normalize(raw, source_key)
            if event:
                results.append(event)
        return results

    # ── Step 2: Field Mapping ──

    def _step2_map_fields(self, raw: Dict) -> NormalizedEvent:
        """Map source fields to NormalizedEvent using field_mapping."""
        event = NormalizedEvent()
        event.category = self.category
        event.source_type = self.source_type
        event.scan_run_id = self.scan_run_id
        event.tenant_id = self.tenant_id

        for target_field, source_path in self.field_mapping.items():
            value = _extract_nested(raw, source_path)
            if value is None:
                continue
            _set_field(event, target_field, value)

        # Generate event_id if not mapped
        if not event.event_id:
            event.event_id = _generate_event_id(raw, self.source_type)

        event.raw_event = raw
        return event

    # ── Step 3: Flatten nested structures ──

    def _step3_flatten(self, event: NormalizedEvent, raw: Dict):
        """Flatten nested actor/resource from raw event."""

        # ── Actor ──
        ui = raw.get("userIdentity", {})
        if isinstance(ui, dict):
            if not event.actor.principal:
                event.actor.principal = ui.get("arn", ui.get("userName", ""))
            # Principal type: Root, IAMUser, AssumedRole, AWSService, FederatedUser
            event.actor.principal_type = ui.get("type", "").lower()
            event.actor.account_id = ui.get("accountId", "")
            # Session name (role session)
            session = ui.get("sessionContext", {})
            if isinstance(session, dict):
                issuer = session.get("sessionIssuer", {})
                if issuer:
                    event.actor.session_name = issuer.get("userName", "")
                # MFA check
                attrs = session.get("attributes", {})
                if isinstance(attrs, dict):
                    event.actor.mfa_used = attrs.get("mfaAuthenticated") == "true"
            # Service invoked by (for service-initiated calls)
            invoked_by = ui.get("invokedBy", "")
            if invoked_by and not event.actor.ip_address:
                event.actor.ip_address = invoked_by

        # ── Resource ──
        # Strategy 1: resources[] array (S3 data events, some services)
        if not event.resource.uid:
            resources = raw.get("resources", [])
            if resources and isinstance(resources, list):
                r = resources[0]
                event.resource.uid = r.get("ARN", r.get("arn", ""))
                event.resource.resource_type = r.get("type", "")
                event.resource.account_id = r.get("accountId", "")

        # Strategy 2: requestParameters (most CloudTrail events)
        if not event.resource.uid:
            params = raw.get("requestParameters") or {}
            if isinstance(params, dict):
                svc = event.service or raw.get("_service", "")
                region = event.resource.region or raw.get("awsRegion", "")
                account = event.actor.account_id or ""

                # 2a: Direct ARN/ID fields (flat)
                for arn_field in ["arn", "resourceArn", "functionArn", "roleArn",
                                   "policyArn", "certificateArn", "topicArn",
                                   "queueUrl", "streamName", "keyId",
                                   "trailName", "trailARN", "detectorId",
                                   "bucketName", "tableName", "clusterName",
                                   "dbInstanceIdentifier", "logGroupName",
                                   "repositoryName", "userName", "roleName",
                                   "groupName", "policyName",
                                   "instanceId", "vpcId", "subnetId",
                                   "securityGroupId", "groupId",
                                   "networkInterfaceId", "allocationId",
                                   "imageId", "volumeId", "snapshotId",
                                   "natGatewayId", "internetGatewayId",
                                   "routeTableId", "networkAclId",
                                   "launchTemplateId", "autoScalingGroupName"]:
                    val = params.get(arn_field)
                    if val and isinstance(val, str):
                        if val.startswith("arn:"):
                            event.resource.uid = val
                        else:
                            event.resource.uid = f"arn:aws:{svc}:{region}:{account}:{arn_field}/{val}"
                        event.resource.name = val
                        break

                # 2b: Nested arrays — instancesSet.items, subnetIdSet.items, etc.
                if not event.resource.uid:
                    for set_field, id_field in [
                        ("instancesSet", "instanceId"),
                        ("subnetIdSet", "subnetId"),
                        ("securityGroupIdSet", "groupId"),
                        ("routeTableIdSet", "routeTableId"),
                        ("networkAclIdSet", "networkAclId"),
                        ("vpcIdSet", "vpcId"),
                        ("autoScalingGroupNames", None),
                    ]:
                        set_data = params.get(set_field)
                        if not set_data:
                            continue
                        # Array of strings: ["name1", "name2"]
                        if isinstance(set_data, list) and set_data:
                            val = set_data[0] if isinstance(set_data[0], str) else None
                            if val:
                                event.resource.uid = f"arn:aws:{svc}:{region}:{account}:{set_field}/{val}"
                                event.resource.name = val
                                break
                        # Dict with items: {items: [{instanceId: "i-123"}]}
                        if isinstance(set_data, dict):
                            items = set_data.get("items", [])
                            if items and isinstance(items, list) and isinstance(items[0], dict):
                                val = items[0].get(id_field, "")
                                if val:
                                    event.resource.uid = f"arn:aws:{svc}:{region}:{account}:{id_field}/{val}"
                                    event.resource.name = val
                                    break

                # 2c: Nested wrapper keys (e.g., DescribeLaunchTemplateVersionsRequest)
                if not event.resource.uid:
                    for wrapper_key, nested_fields in [
                        ("DescribeLaunchTemplateVersionsRequest", ["LaunchTemplateName", "LaunchTemplateId"]),
                        ("DescribeLoadBalancersRequest", ["LoadBalancerNames"]),
                    ]:
                        wrapper = params.get(wrapper_key)
                        if isinstance(wrapper, dict):
                            for nf in nested_fields:
                                val = wrapper.get(nf)
                                if val and isinstance(val, str):
                                    event.resource.uid = f"arn:aws:{svc}:{region}:{account}:{nf}/{val}"
                                    event.resource.name = val
                                    break
                        if event.resource.uid:
                            break

                # 2d: EKS/ECS specific params
                if not event.resource.uid:
                    cluster = params.get("name", params.get("clusterName", ""))
                    nodegroup = params.get("nodegroupName", "")
                    if cluster and nodegroup:
                        event.resource.uid = f"arn:aws:eks:{region}:{account}:nodegroup/{cluster}/{nodegroup}"
                        event.resource.name = f"{cluster}/{nodegroup}"
                    elif cluster:
                        event.resource.uid = f"arn:aws:eks:{region}:{account}:cluster/{cluster}"
                        event.resource.name = cluster

                # 2e: No params at all (GetCallerIdentity) — use actor
                if not event.resource.uid:
                    if params is None or params == {} or (isinstance(params, dict) and not params):
                        if event.actor.principal:
                            event.resource.uid = event.actor.principal
                            event.resource.name = event.actor.session_name or event.actor.principal.split("/")[-1]

                # 2f: Filter-only queries — use actor + operation for tracking
                if not event.resource.uid and (params.get("filterSet") or params.get("filters")):
                    event.resource.uid = f"{svc}:{event.operation}:query"

        # Strategy 3: responseElements (for Create operations that return the new resource)
        if not event.resource.uid:
            resp = raw.get("responseElements") or {}
            if isinstance(resp, dict):
                for arn_field in ["arn", "instanceId", "vpcId", "groupId",
                                   "keyMetadata.Arn", "role.Arn", "user.Arn"]:
                    if "." in arn_field:
                        parts = arn_field.split(".")
                        val = resp.get(parts[0], {})
                        if isinstance(val, dict):
                            val = val.get(parts[1])
                    else:
                        val = resp.get(arn_field)
                    if val and isinstance(val, str):
                        event.resource.uid = val
                        break

        # ── Resource type from ARN pattern ──
        if event.resource.uid and event.resource.uid.startswith("arn:") and not event.resource.resource_type:
            # arn:aws:SERVICE:region:account:RESOURCE_TYPE/id
            parts = event.resource.uid.split(":")
            if len(parts) >= 6:
                svc = parts[2]
                res_part = parts[5]
                if "/" in res_part:
                    event.resource.resource_type = f"{svc}.{res_part.split('/')[0]}"
                elif res_part:
                    event.resource.resource_type = f"{svc}.{res_part}"

        # ── Resource type fallback from service + operation ──
        if not event.resource.resource_type and event.service:
            op = event.operation or ""
            for prefix in ["Describe", "List", "Get", "Create", "Delete",
                           "Update", "Modify", "Put", "Attach", "Detach"]:
                if op.startswith(prefix):
                    noun = op[len(prefix):]
                    if noun:
                        event.resource.resource_type = f"{event.service}.{noun}"
                    break

    # ── Step 4: Type conversion ──

    def _step4_type_convert(self, event: NormalizedEvent, raw: Dict):
        """Convert timestamps, IPs, ports to proper types."""
        # Timestamp
        if not event.event_time:
            for ts_field in ["eventTime", "timestamp", "time", "start_time"]:
                ts_val = raw.get(ts_field)
                if ts_val:
                    event.event_time = _parse_timestamp(ts_val)
                    break
        if not event.event_time:
            event.event_time = datetime.now(timezone.utc)

        event.ingestion_time = datetime.now(timezone.utc)

        # Network ports
        if event.network:
            if isinstance(event.network.src_port, str):
                event.network.src_port = int(event.network.src_port) if event.network.src_port.isdigit() else 0
            if isinstance(event.network.dst_port, str):
                event.network.dst_port = int(event.network.dst_port) if event.network.dst_port.isdigit() else 0
            if isinstance(event.network.bytes_in, str):
                event.network.bytes_in = int(event.network.bytes_in) if event.network.bytes_in.isdigit() else 0
            if isinstance(event.network.packets, str):
                event.network.packets = int(event.network.packets) if event.network.packets.isdigit() else 0

        # Outcome
        if not event.outcome or event.outcome == "unknown":
            error = raw.get("errorCode") or raw.get("error_code")
            if error:
                event.outcome = EventOutcome.FAILURE
                event.error_code = str(error)
                event.error_message = raw.get("errorMessage", "")
            elif raw.get("responseElements") is not None or raw.get("status") == "Success":
                event.outcome = EventOutcome.SUCCESS

    # ── Step 5: Source metadata ──

    def _step5_source_metadata(self, event: NormalizedEvent, source_key: str):
        """Add where this event came from."""
        event.source_bucket = self.source_bucket
        event.source_key = source_key
        event.source_region = self.source_region or event.resource.region or ""

        # Default resource region from event if not set
        if not event.resource.region:
            event.resource.region = (
                event.raw_event.get("awsRegion")
                or event.raw_event.get("region")
                or self.source_region
                or ""
            )

    # ── Step 6: Enrichment ──

    def _step6_enrich(self, event: NormalizedEvent):
        """Enrich with inventory data, risk indicators, and classification."""

        # ── Identifier-based UID construction ──
        # Use resource_inventory_identifier patterns to build proper ARNs
        if (not event.resource.uid or not event.resource.uid.startswith("arn:")) and self.identifier_index:
            self._build_uid_from_identifier(event)

        # ── Asset matching (lookup resource in inventory) ──
        if event.resource.uid:
            # Try exact match
            if event.resource.uid in self.asset_index:
                event.asset_matched = True
                asset = self.asset_index[event.resource.uid]
                if not event.resource.resource_type:
                    event.resource.resource_type = asset.get("resource_type", "")
                if not event.resource.name:
                    event.resource.name = asset.get("name", "")
            # Try partial match (arn prefix)
            elif event.resource.uid.startswith("arn:"):
                for uid, asset in self.asset_index.items():
                    if uid.startswith(event.resource.uid[:50]):
                        event.asset_matched = True
                        if not event.resource.resource_type:
                            event.resource.resource_type = asset.get("resource_type", "")
                        break

        # ── Risk indicators ──
        indicators = event.risk_indicators

        # Authentication
        if event.actor.principal_type == "root":
            indicators.append("root_account_usage")
        if event.actor.mfa_used is False and event.operation == "ConsoleLogin":
            indicators.append("no_mfa")

        # Access failures
        if event.outcome == EventOutcome.FAILURE:
            if event.error_code in ("AccessDenied", "UnauthorizedAccess", "AccessDeniedException"):
                indicators.append("access_denied")
            elif event.error_code in ("Client.UnauthorizedAccess", "Forbidden"):
                indicators.append("access_denied")

        # Network — only flag truly external IPs (not AWS services, not private)
        ip = event.actor.ip_address or ""
        is_aws_service = ip.endswith(".amazonaws.com") or ip.endswith(".aws.internal")
        is_private = ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                    "172.2", "172.30.", "172.31.", "192.168.", "127."))
        if ip and not is_aws_service and not is_private and "." in ip:
            indicators.append("external_ip")

        # Destructive actions
        op = event.operation or ""
        if any(op.startswith(p) for p in ("Delete", "Terminate", "Remove", "Purge", "Destroy")):
            indicators.append("destructive_action")
        # Defense evasion
        if op in ("StopLogging", "DeleteTrail", "UpdateTrail", "DeleteFlowLogs",
                   "DeleteDetector", "DisableKey", "ScheduleKeyDeletion",
                   "DeleteAlarm", "DeleteEventSubscription"):
            indicators.append("defense_evasion")
        # Privilege changes
        if op in ("CreateUser", "CreateAccessKey", "CreateLoginProfile",
                   "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
                   "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
                   "UpdateAssumeRolePolicy", "CreateRole",
                   "DeleteRolePermissionsBoundary", "DeleteUserPermissionsBoundary"):
            indicators.append("privilege_change")
        # Data exposure
        if op in ("PutBucketPolicy", "PutBucketAcl", "DeletePublicAccessBlock",
                   "PutPublicAccessBlock", "ModifyDBSnapshotAttribute",
                   "ModifySnapshotAttribute"):
            indicators.append("data_exposure")
        # Data access
        if op in ("GetObject", "PutObject", "CopyObject", "DeleteObject"):
            indicators.append("data_access")

        # ── Severity ──
        if "defense_evasion" in indicators or "root_account_usage" in indicators:
            event.severity = "critical"
        elif "destructive_action" in indicators or "data_exposure" in indicators:
            event.severity = "high"
        elif "privilege_change" in indicators or "no_mfa" in indicators:
            event.severity = "medium"
        elif "access_denied" in indicators:
            event.severity = "low"
        # else: stays "info"

    def _build_uid_from_identifier(self, event: NormalizedEvent):
        """Build resource_uid using identifier_pattern from resource_inventory_identifier.

        Matches operation → resource_type → identifier_pattern, then fills
        template variables from requestParameters.

        Example:
          operation: DescribeInstances
          resource_type: ec2.instance
          pattern: arn:${Partition}:ec2:${Region}:${Account}:instance/${InstanceId}
          requestParameters: {instancesSet: {items: [{instanceId: "i-abc"}]}}
          → arn:aws:ec2:ap-south-1:588989875114:instance/i-abc
        """
        import re as _re

        svc = event.service or ""
        op = event.operation or ""
        raw = event.raw_event or {}
        params = raw.get("requestParameters") or {}
        if not isinstance(params, dict):
            return

        region = event.resource.region or raw.get("awsRegion", "")
        account = event.actor.account_id or ""

        # Infer resource_type from operation name
        resource_noun = ""
        for prefix in ["Describe", "List", "Get", "Create", "Delete",
                        "Update", "Modify", "Put", "Attach", "Detach",
                        "Start", "Stop", "Terminate", "Enable", "Disable"]:
            if op.startswith(prefix):
                resource_noun = op[len(prefix):]
                break

        if not resource_noun:
            return

        # Try to find matching identifier entry
        # Check variations: ec2.instance, ec2.instances, ec2.Instance
        candidates = [
            f"{svc}.{resource_noun}",
            f"{svc}.{resource_noun.lower()}",
            f"{svc}.{resource_noun.rstrip('s')}",  # Instances → Instance
            f"{svc}.{resource_noun.rstrip('es')}",
        ]

        pattern_entry = None
        for candidate in candidates:
            if candidate in self.identifier_index:
                pattern_entry = self.identifier_index[candidate]
                break

        if not pattern_entry:
            return

        pattern = pattern_entry.get("identifier_pattern", "")
        primary_param = pattern_entry.get("primary_param", "")
        if not pattern:
            return

        # Collect ALL values from requestParameters (flat + nested)
        all_values = {}
        for k, v in params.items():
            if isinstance(v, str):
                all_values[k] = v
            elif isinstance(v, dict):
                # Nested: {items: [{key: val}]}
                items = v.get("items", [])
                if items and isinstance(items, list) and isinstance(items[0], dict):
                    all_values.update(items[0])
                # Nested: {key: val}
                for nk, nv in v.items():
                    if isinstance(nv, str):
                        all_values[nk] = nv

        # Also check responseElements for Create operations
        resp = raw.get("responseElements") or {}
        if isinstance(resp, dict):
            for k, v in resp.items():
                if isinstance(v, str) and k not in all_values:
                    all_values[k] = v
                elif isinstance(v, dict):
                    for nk, nv in v.items():
                        if isinstance(nv, str) and nk not in all_values:
                            all_values[nk] = nv

        # Fill template
        uid = pattern
        uid = uid.replace("${Partition}", "aws")
        uid = uid.replace("${Region}", region)
        uid = uid.replace("${Account}", account)

        # Replace remaining ${Field} with values from params
        missing = False
        for match in _re.findall(r'\$\{(\w+)\}', uid):
            # Try exact match, then case-insensitive
            val = all_values.get(match)
            if not val:
                val = all_values.get(match[0].lower() + match[1:])
            if not val:
                # Try primary_param
                if primary_param:
                    val = all_values.get(primary_param)
            if val:
                uid = uid.replace(f"${{{match}}}", str(val))
            else:
                missing = True
                break

        if not missing and uid.startswith("arn:") and "${" not in uid:
            event.resource.uid = uid
            if not event.resource.resource_type:
                event.resource.resource_type = pattern_entry.get("canonical_type", "")
                if event.resource.resource_type:
                    event.resource.resource_type = f"{svc}.{event.resource.resource_type}"


# ── Utility Functions ──

def _extract_nested(data: Dict, path: str) -> Any:
    """Extract a value from a nested dict using dot-path. e.g. 'userIdentity.arn'"""
    parts = path.split(".")
    current = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _set_field(event: NormalizedEvent, target: str, value: Any):
    """Set a field on NormalizedEvent, supporting nested paths like 'actor.ip_address'.

    Auto-creates NetworkInfo/HttpInfo when setting network.*/http.* fields.
    """
    parts = target.split(".")
    obj = event
    for part in parts[:-1]:
        child = getattr(obj, part, None)
        if child is None:
            # Auto-create nested objects
            if part == "network":
                child = NetworkInfo()
                setattr(obj, part, child)
            elif part == "http":
                child = HttpInfo()
                setattr(obj, part, child)
            else:
                return
        obj = child
    setattr(obj, parts[-1], value)


def _generate_event_id(raw: Dict, source_type: str) -> str:
    """Generate deterministic event ID from raw event."""
    if source_type == "vpc_flow":
        # VPC Flow: use all unique fields to avoid collisions
        key_parts = [
            source_type,
            str(raw.get("account_id", "")),
            str(raw.get("interface_id", "")),
            str(raw.get("srcaddr", "")),
            str(raw.get("dstaddr", "")),
            str(raw.get("srcport", "")),
            str(raw.get("dstport", "")),
            str(raw.get("protocol", "")),
            str(raw.get("start", "")),
            str(raw.get("end", "")),
        ]
    else:
        key_parts = [
            source_type,
            str(raw.get("eventID", raw.get("event_id", ""))),
            str(raw.get("eventTime", raw.get("timestamp", ""))),
            str(raw.get("sourceIPAddress", raw.get("srcaddr", ""))),
        ]
    return hashlib.sha256("|".join(key_parts).encode()).hexdigest()[:20]


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse various timestamp formats to datetime."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        # Unix epoch (seconds or milliseconds)
        if value > 1e12:
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",  # S3 access log format
        ):
            try:
                return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None
