"""
SQLAlchemy models for PostgreSQL database
"""
from sqlalchemy import Column, String, Integer, Boolean, Text, TIMESTAMP, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

Base = declarative_base()


class Tenant(Base):
    """Tenant model"""
    __tablename__ = 'tenants'

    tenant_id = Column(String(255), primary_key=True)
    tenant_name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    status = Column(String(50), nullable=False, default='active')
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    providers = relationship("Provider", back_populates="tenant", cascade="all, delete-orphan")
    accounts = relationship("Account", back_populates="tenant", cascade="all, delete-orphan")
    schedules = relationship("Schedule", back_populates="tenant", cascade="all, delete-orphan")


class Provider(Base):
    """Provider model"""
    __tablename__ = 'providers'

    provider_id = Column(String(255), primary_key=True)
    tenant_id = Column(String(255), ForeignKey('tenants.tenant_id', ondelete='CASCADE'), nullable=False)
    provider_type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False, default='active')
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    tenant = relationship("Tenant", back_populates="providers")
    accounts = relationship("Account", back_populates="provider", cascade="all, delete-orphan")

    __table_args__ = (
        {'extend_existing': True},
    )


class Account(Base):
    """Account model"""
    __tablename__ = 'accounts'

    account_id = Column(String(255), primary_key=True)
    provider_id = Column(String(255), ForeignKey('providers.provider_id', ondelete='CASCADE'), nullable=False)
    tenant_id = Column(String(255), ForeignKey('tenants.tenant_id', ondelete='CASCADE'), nullable=False)
    account_name = Column(String(255), nullable=False)
    account_number = Column(String(50))
    status = Column(String(50), nullable=False, default='pending')
    onboarding_status = Column(String(50), nullable=False, default='pending')
    onboarding_id = Column(String(255))
    last_validated_at = Column(TIMESTAMP(timezone=True))
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    provider = relationship("Provider", back_populates="accounts")
    tenant = relationship("Tenant", back_populates="accounts")
    schedules = relationship("Schedule", back_populates="account", cascade="all, delete-orphan")
    executions = relationship("Execution", back_populates="account", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="account", cascade="all, delete-orphan")


class Schedule(Base):
    """Schedule model"""
    __tablename__ = 'schedules'

    schedule_id = Column(String(255), primary_key=True)
    tenant_id = Column(String(255), ForeignKey('tenants.tenant_id', ondelete='CASCADE'), nullable=False)
    account_id = Column(String(255), ForeignKey('accounts.account_id', ondelete='CASCADE'), nullable=False)
    name = Column(String(255), nullable=False)
    schedule_type = Column(String(50), nullable=False)
    provider_type = Column(String(50), nullable=False)
    cron_expression = Column(String(255))
    interval_seconds = Column(Integer, default=0)
    regions = Column(JSONB, default=[])
    services = Column(JSONB, default=[])
    exclude_services = Column(JSONB, default=[])
    timezone = Column(String(50), nullable=False, default='UTC')
    status = Column(String(50), nullable=False, default='active')
    enabled = Column(Boolean, nullable=False, default=True)
    next_run_at = Column(TIMESTAMP(timezone=True))
    run_count = Column(Integer, nullable=False, default=0)
    success_count = Column(Integer, nullable=False, default=0)
    failure_count = Column(Integer, nullable=False, default=0)
    notify_on_success = Column(Boolean, nullable=False, default=False)
    notify_on_failure = Column(Boolean, nullable=False, default=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    tenant = relationship("Tenant", back_populates="schedules")
    account = relationship("Account", back_populates="schedules")
    executions = relationship("Execution", back_populates="schedule", cascade="all, delete-orphan")


class Execution(Base):
    """Execution model"""
    __tablename__ = 'executions'

    execution_id = Column(String(255), primary_key=True)
    schedule_id = Column(String(255), ForeignKey('schedules.schedule_id', ondelete='CASCADE'), nullable=False)
    account_id = Column(String(255), ForeignKey('accounts.account_id', ondelete='CASCADE'), nullable=False)
    scan_id = Column(String(255))
    started_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(TIMESTAMP(timezone=True))
    status = Column(String(50), nullable=False, default='running')
    triggered_by = Column(String(50), nullable=False, default='scheduler')
    total_checks = Column(Integer)
    passed_checks = Column(Integer)
    failed_checks = Column(Integer)
    error_message = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())

    # Relationships
    schedule = relationship("Schedule", back_populates="executions")
    account = relationship("Account", back_populates="executions")


class ScanResult(Base):
    """Scan result model"""
    __tablename__ = 'scan_results'

    scan_id = Column(String(255), primary_key=True)
    account_id = Column(String(255), ForeignKey('accounts.account_id', ondelete='CASCADE'), nullable=False)
    provider_type = Column(String(50), nullable=False)
    scan_type = Column(String(50), nullable=False, default='scheduled')
    started_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(TIMESTAMP(timezone=True))
    status = Column(String(50), nullable=False, default='running')
    total_checks = Column(Integer)
    passed_checks = Column(Integer)
    failed_checks = Column(Integer)
    error_checks = Column(Integer)
    result_storage_path = Column(Text)
    scan_metadata = Column(JSONB, name='metadata')  # Column name in DB is 'metadata', but Python attribute is 'scan_metadata' to avoid SQLAlchemy conflict
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=func.now())

    # Relationships
    account = relationship("Account", back_populates="scan_results")

