"""
SQLAlchemy ORM models for threat_engine_onboarding database.

Tables:
    tenants          — customer workspaces
    cloud_accounts   — one row per cloud account (AWS/Azure/GCP etc.)
    schedules        — scan schedules (separate table, multiple per account)
    scan_runs        — every scan execution (was scan_orchestration)
    account_hierarchy — AWS Org / multi-account tree (unmanaged here, read-only)
"""
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.types import TIMESTAMP
import uuid

Base = declarative_base()


# ---------------------------------------------------------------------------
# Tenant
# ---------------------------------------------------------------------------

class Tenant(Base):
    """
    Customer workspace. Groups cloud accounts under a named organization.
    tenant_id is VARCHAR to match existing data (not UUID).
    """
    __tablename__ = 'tenants'

    tenant_id           = Column(String(255), primary_key=True)
    customer_id         = Column(String(255), nullable=False, index=True)
    tenant_name         = Column(String(255), nullable=False)
    tenant_description  = Column(Text)
    status              = Column(String(50), nullable=False, default='active')
    created_at          = Column(TIMESTAMP(timezone=True), nullable=False,
                                 server_default=func.now())
    updated_at          = Column(TIMESTAMP(timezone=True), nullable=False,
                                 server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint('customer_id', 'tenant_name', name='uq_customer_tenant_name'),
    )

    # Relationships
    cloud_accounts = relationship('CloudAccount', back_populates='tenant',
                                  cascade='all, delete-orphan')
    schedules      = relationship('Schedule', back_populates='tenant',
                                  cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'tenant_id':          self.tenant_id,
            'customer_id':        self.customer_id,
            'tenant_name':        self.tenant_name,
            'tenant_description': self.tenant_description,
            'status':             self.status,
            'created_at':         self.created_at.isoformat() if self.created_at else None,
            'updated_at':         self.updated_at.isoformat() if self.updated_at else None,
        }


# ---------------------------------------------------------------------------
# CloudAccount
# ---------------------------------------------------------------------------

class CloudAccount(Base):
    """
    One row per cloud account (AWS account ID, Azure subscription, GCP project, etc.)
    Credentials stored in AWS Secrets Manager; credential_ref is the path.
    Schedule config lives in the schedules table (FK: schedules.account_id).
    """
    __tablename__ = 'cloud_accounts'

    # Identity
    account_id      = Column(String(255), primary_key=True)
    customer_id     = Column(String(255), nullable=False, index=True)
    tenant_id       = Column(String(255),
                             ForeignKey('tenants.tenant_id', ondelete='RESTRICT'),
                             nullable=False, index=True)

    # Account metadata
    account_name            = Column(String(255), nullable=False)
    account_number          = Column(String(255))          # provider-detected ID
    account_hierarchy_name  = Column(String(255))          # display path in org tree
    provider                = Column(String(50), nullable=False)   # aws/azure/gcp/oci/alicloud/ibm/k8s

    # Credentials (stored in Secrets Manager)
    credential_type         = Column(String(50), nullable=False)   # iam_role/access_key/service_principal/...
    credential_ref          = Column(String(500), nullable=False)  # secrets manager path or ARN

    # Lifecycle status
    account_status          = Column(String(50), nullable=False, default='pending')
    # pending → active → inactive → deleted
    onboarding_status       = Column(String(50), nullable=False, default='pending',
                                     key='account_onboarding_status')
    # pending → deployed → validated
    onboarding_id           = Column(String(255), key='account_onboarding_id')  # CF stack ID etc.

    # Credential validation
    credential_validation_status    = Column(String(50), default='pending')
    # pending → valid → invalid → expired
    credential_validation_message   = Column(Text)
    credential_validated_at         = Column(TIMESTAMP(timezone=True),
                                             key='account_last_validated_at')
    credential_validation_errors    = Column(JSONB, default=list)

    # CIEM log source config
    log_sources     = Column(JSONB, default=dict)

    # Scan tracking
    last_scan_at    = Column(TIMESTAMP(timezone=True))

    # Timestamps
    created_at      = Column(TIMESTAMP(timezone=True), nullable=False,
                             server_default=func.now())
    updated_at      = Column(TIMESTAMP(timezone=True), nullable=False,
                             server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint('customer_id', 'tenant_id', 'account_name',
                         name='unique_customer_tenant_account'),
    )

    # Relationships
    tenant    = relationship('Tenant', back_populates='cloud_accounts')
    schedules = relationship('Schedule', back_populates='cloud_account',
                             cascade='all, delete-orphan')
    scan_runs = relationship('ScanRun', back_populates='cloud_account')

    def to_dict(self):
        return {
            'account_id':                   self.account_id,
            'customer_id':                  self.customer_id,
            'tenant_id':                    self.tenant_id,
            'account_name':                 self.account_name,
            'account_number':               self.account_number,
            'provider':                     self.provider,
            'credential_type':              self.credential_type,
            'credential_ref':               self.credential_ref,
            'account_status':               self.account_status,
            'onboarding_status':            self.onboarding_status,
            'credential_validation_status': self.credential_validation_status,
            'credential_validated_at':      self.credential_validated_at.isoformat()
                                            if self.credential_validated_at else None,
            'credential_validation_errors': self.credential_validation_errors or [],
            'log_sources':                  self.log_sources or {},
            'last_scan_at':                 self.last_scan_at.isoformat()
                                            if self.last_scan_at else None,
            'created_at':                   self.created_at.isoformat()
                                            if self.created_at else None,
            'updated_at':                   self.updated_at.isoformat()
                                            if self.updated_at else None,
        }


# ---------------------------------------------------------------------------
# Schedule
# ---------------------------------------------------------------------------

class Schedule(Base):
    """
    Scan schedule for a cloud account.
    Multiple schedules per account are allowed (e.g. full weekly + compliance daily).
    Scheduler polls: WHERE enabled = true AND next_run_at <= NOW()
    """
    __tablename__ = 'schedules'

    schedule_id     = Column(UUID(as_uuid=True), primary_key=True,
                             default=uuid.uuid4)
    account_id      = Column(String(255),
                             ForeignKey('cloud_accounts.account_id', ondelete='CASCADE'),
                             nullable=False, index=True)
    tenant_id       = Column(String(255),
                             ForeignKey('tenants.tenant_id', ondelete='CASCADE'),
                             nullable=False, index=True)
    customer_id     = Column(String(255), nullable=False, index=True)

    schedule_name   = Column(String(255))
    cron_expression = Column(String(255), nullable=False, default='0 2 * * 0')
    timezone        = Column(String(50), nullable=False, default='UTC')
    enabled         = Column(Boolean, nullable=False, default=True)

    # Scan scope (null = all)
    include_regions     = Column(JSONB)
    include_services    = Column(JSONB)
    exclude_services    = Column(JSONB)
    engines_requested   = Column(JSONB, nullable=False, default=lambda: [
        'discovery', 'check', 'inventory', 'threat', 'compliance', 'iam', 'datasec'
    ])

    # Execution tracking
    next_run_at     = Column(TIMESTAMP(timezone=True))
    last_run_at     = Column(TIMESTAMP(timezone=True))
    run_count       = Column(Integer, nullable=False, default=0)
    success_count   = Column(Integer, nullable=False, default=0)
    failure_count   = Column(Integer, nullable=False, default=0)

    # Notifications
    notify_on_success   = Column(Boolean, nullable=False, default=False)
    notify_on_failure   = Column(Boolean, nullable=False, default=True)
    notification_emails = Column(JSONB)

    created_at  = Column(TIMESTAMP(timezone=True), nullable=False,
                         server_default=func.now())
    updated_at  = Column(TIMESTAMP(timezone=True), nullable=False,
                         server_default=func.now(), onupdate=func.now())

    # Relationships
    cloud_account = relationship('CloudAccount', back_populates='schedules')
    tenant        = relationship('Tenant', back_populates='schedules')
    scan_runs     = relationship('ScanRun', back_populates='schedule')

    def to_dict(self):
        return {
            'schedule_id':        str(self.schedule_id),
            'account_id':         self.account_id,
            'tenant_id':          self.tenant_id,
            'customer_id':        self.customer_id,
            'schedule_name':      self.schedule_name,
            'cron_expression':    self.cron_expression,
            'timezone':           self.timezone,
            'enabled':            self.enabled,
            'include_regions':    self.include_regions,
            'include_services':   self.include_services,
            'exclude_services':   self.exclude_services,
            'engines_requested':  self.engines_requested,
            'next_run_at':        self.next_run_at.isoformat() if self.next_run_at else None,
            'last_run_at':        self.last_run_at.isoformat() if self.last_run_at else None,
            'run_count':          self.run_count,
            'success_count':      self.success_count,
            'failure_count':      self.failure_count,
            'notify_on_success':  self.notify_on_success,
            'notify_on_failure':  self.notify_on_failure,
            'notification_emails': self.notification_emails,
            'created_at':         self.created_at.isoformat() if self.created_at else None,
            'updated_at':         self.updated_at.isoformat() if self.updated_at else None,
        }


# ---------------------------------------------------------------------------
# ScanRun
# ---------------------------------------------------------------------------

class ScanRun(Base):
    """
    Every scan execution — scheduled or manual.
    Was: scan_orchestration table.
    scan_run_id is the single identifier passed to ALL engines.

    engine_statuses tracks per-engine progress:
        {
          "discovery":  {"status": "completed", "findings": 120, "duration_seconds": 45},
          "check":      {"status": "running"},
          "inventory":  {"status": "pending"},
          ...
        }
    overall_status auto-set to "completed" when all engines_requested are done.
    """
    __tablename__ = 'scan_runs'

    scan_run_id     = Column(UUID(as_uuid=True), primary_key=True,
                             default=uuid.uuid4)

    # Ownership
    customer_id     = Column(String(255), nullable=False, index=True)
    tenant_id       = Column(String(255), nullable=False, index=True)
    account_id      = Column(String(255),
                             ForeignKey('cloud_accounts.account_id', ondelete='SET NULL'),
                             nullable=True, index=True)

    # Link to schedule (null = manual / API trigger)
    schedule_id     = Column(String(255), index=True)     # legacy VARCHAR FK
    schedule_uuid   = Column(UUID(as_uuid=True),
                             ForeignKey('schedules.schedule_id', ondelete='SET NULL'),
                             nullable=True)

    # Cloud provider context
    provider        = Column(String(50), nullable=False)
    credential_type = Column(String(50), nullable=False)
    credential_ref  = Column(String(500), nullable=False)

    # Scan metadata
    scan_name       = Column(String(255))
    scan_type       = Column(String(50), nullable=False, default='full')
    # full | partial
    trigger_type    = Column(String(50), nullable=False, default='scheduled')
    # scheduled | manual | api

    # Scope
    include_regions     = Column(JSONB)
    include_services    = Column(JSONB)
    exclude_services    = Column(JSONB)

    # Engine tracking
    engines_requested   = Column(JSONB, nullable=False)
    engines_completed   = Column(JSONB, default=list)
    engine_statuses     = Column(JSONB, default=dict)   # per-engine status map

    # Overall status
    overall_status  = Column(String(50), nullable=False, default='pending')
    # pending → running → completed | failed | cancelled

    # Timestamps
    started_at      = Column(TIMESTAMP(timezone=True), nullable=False,
                             server_default=func.now())
    completed_at    = Column(TIMESTAMP(timezone=True))
    created_at      = Column(TIMESTAMP(timezone=True), nullable=False,
                             server_default=func.now())

    # Results
    results_summary = Column(JSONB, default=dict)
    error_details   = Column(JSONB, default=dict)

    # Relationships
    cloud_account   = relationship('CloudAccount', back_populates='scan_runs')
    schedule        = relationship('Schedule', back_populates='scan_runs',
                                   foreign_keys=[schedule_uuid])

    def to_dict(self):
        return {
            'scan_run_id':        str(self.scan_run_id),
            'customer_id':        self.customer_id,
            'tenant_id':          self.tenant_id,
            'account_id':         self.account_id,
            'schedule_id':        self.schedule_id,
            'provider':           self.provider,
            'credential_type':    self.credential_type,
            'scan_name':          self.scan_name,
            'scan_type':          self.scan_type,
            'trigger_type':       self.trigger_type,
            'include_regions':    self.include_regions,
            'include_services':   self.include_services,
            'engines_requested':  self.engines_requested,
            'engines_completed':  self.engines_completed or [],
            'engine_statuses':    self.engine_statuses or {},
            'overall_status':     self.overall_status,
            'started_at':         self.started_at.isoformat() if self.started_at else None,
            'completed_at':       self.completed_at.isoformat() if self.completed_at else None,
            'results_summary':    self.results_summary or {},
            'error_details':      self.error_details or {},
        }


# ---------------------------------------------------------------------------
# AccountHierarchy (read-only — managed by discovery engine)
# ---------------------------------------------------------------------------

class AccountHierarchy(Base):
    """
    AWS Org / multi-account hierarchy tree. Written by discovery engine.
    Onboarding reads it to display org structure. Do not write from onboarding.
    """
    __tablename__ = 'account_hierarchy'

    id              = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id       = Column(String(255), index=True)
    customer_id     = Column(String(255), index=True)
    node_id         = Column(String(255))
    node_name       = Column(String(255))
    node_type       = Column(String(255))   # ROOT / OU / ACCOUNT
    parent_node_id  = Column(String(255))
    hierarchy_path  = Column(Text)
    depth           = Column(Integer)
    provider        = Column(String(255))
    provider_org_id = Column(String(255))
    status          = Column(String(255))
    node_metadata   = Column('metadata', JSONB)   # 'metadata' is reserved by SQLAlchemy declarative
    discovered_at   = Column(TIMESTAMP(timezone=True))
    updated_at      = Column(TIMESTAMP(timezone=True))
