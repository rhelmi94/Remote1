from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
import json
from datetime import datetime, timedelta
from enum import Enum

class UserRole(Enum):
    SUPER_ADMIN = 'super_admin'
    ADMIN = 'admin'
    USER = 'user'
    CUSTOMER = 'customer'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(32), default=UserRole.USER.value)
    phone_number = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))

    # Define relationships
    created_scripts = db.relationship('RemoteScript', backref='author',
                                    foreign_keys='RemoteScript.created_by')
    monitored_devices = db.relationship('DeviceSession', backref='monitoring_user',
                                      foreign_keys='DeviceSession.user_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_super_admin(self):
        return self.role == UserRole.SUPER_ADMIN.value

    @property
    def is_admin(self):
        return self.role in [UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value]

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    port = db.Column(db.Integer)
    platform = db.Column(db.String(32))  # Windows, Linux, macOS
    os_version = db.Column(db.String(64))
    cpu_model = db.Column(db.String(128))
    total_memory = db.Column(db.BigInteger)  # Total RAM in bytes
    total_storage = db.Column(db.BigInteger)  # Total storage in bytes
    status = db.Column(db.String(32), default='offline')  # online, offline, warning, error
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_check = db.Column(db.DateTime, default=datetime.utcnow)
    group_id = db.Column(db.Integer, db.ForeignKey('device_group.id'))
    agent_version = db.Column(db.String(32))
    monitoring_profile_id = db.Column(db.Integer, db.ForeignKey('monitoring_profile.id'))
    is_online = db.Column(db.Boolean, default=False)
    latency = db.Column(db.Float)

    # Performance metrics
    cpu_usage = db.Column(db.Float)  # Percentage
    memory_usage = db.Column(db.Float)  # Percentage
    disk_usage = db.Column(db.Float)  # Percentage
    network_in_rate = db.Column(db.Float)  # Bytes per second
    network_out_rate = db.Column(db.Float)  # Bytes per second
    process_count = db.Column(db.Integer)
    temperature = db.Column(db.Float)  # Celsius

    # Health indicators
    health_score = db.Column(db.Integer, default=100)  # 0-100
    cpu_health = db.Column(db.String(32), default='normal')  # critical, warning, normal
    memory_health = db.Column(db.String(32), default='normal')
    disk_health = db.Column(db.String(32), default='normal')
    network_health = db.Column(db.String(32), default='normal')

    # Notes and custom fields
    notes = db.Column(db.Text)
    custom_fields = db.Column(db.Text)  # JSON storage for custom fields

    # Define the relationship with DeviceGroup
    group = db.relationship('DeviceGroup', foreign_keys=[group_id], backref='managed_devices')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'ip_address': self.ip_address,
            'port': self.port,
            'platform': self.platform,
            'status': self.status,
            'is_online': self.is_online,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'health_score': self.health_score,
            'group_id': self.group_id,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'disk_usage': self.disk_usage,
            'agent_version': self.agent_version
        }

    def update_health_score(self):
        scores = []
        if self.cpu_usage is not None:
            scores.append(100 - min(self.cpu_usage, 100))
        if self.memory_usage is not None:
            scores.append(100 - min(self.memory_usage, 100))
        if self.disk_usage is not None:
            scores.append(100 - min(self.disk_usage, 100))

        if scores:
            self.health_score = sum(scores) / len(scores)
            self.update_health_indicators()

    def update_health_indicators(self):
        if self.cpu_usage:
            self.cpu_health = 'critical' if self.cpu_usage > 90 else 'warning' if self.cpu_usage > 75 else 'normal'
        if self.memory_usage:
            self.memory_health = 'critical' if self.memory_usage > 90 else 'warning' if self.memory_usage > 75 else 'normal'
        if self.disk_usage:
            self.disk_health = 'critical' if self.disk_usage > 90 else 'warning' if self.disk_usage > 75 else 'normal'

    def update_status(self, force_offline=False):
        current_time = datetime.utcnow()

        if force_offline:
            self.is_online = False
            self.status = 'offline'
        else:
            # Check if device has been seen in the last 5 minutes
            if self.last_seen and (current_time - self.last_seen).total_seconds() < 300:
                self.is_online = True
                self.status = 'online'

                # Update health-based status
                if self.health_score is not None:
                    if self.health_score < 60:
                        self.status = 'error'
                    elif self.health_score < 80:
                        self.status = 'warning'
            else:
                self.is_online = False
                self.status = 'offline'

        self.last_check = current_time
        db.session.commit()


class DeviceGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    parent_id = db.Column(db.Integer, db.ForeignKey('device_group.id'))

    # Fix the backref conflict by removing the duplicate relationship
    subgroups = db.relationship('DeviceGroup', backref=db.backref('parent', remote_side=[id]))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'device_count': len(self.managed_devices),
            'parent_id': self.parent_id,
            'created_at': self.created_at.isoformat()
        }

class SystemMetric(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_percent = db.Column(db.Float)
    memory_percent = db.Column(db.Float)
    disk_percent = db.Column(db.Float)
    network_in_bytes = db.Column(db.BigInteger)
    network_out_bytes = db.Column(db.BigInteger)
    process_count = db.Column(db.Integer)
    temperature = db.Column(db.Float, nullable=True)

class DeviceSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    session_type = db.Column(db.String(32))  # monitoring, remote_control, etc.
    status = db.Column(db.String(32))  # active, ended, terminated

class RemoteScript(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    script_type = db.Column(db.String(32))  # powershell, cmd, bash, python
    content = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_enabled = db.Column(db.Boolean, default=True)
    target_platform = db.Column(db.String(32))  # windows, linux, macos
    timeout = db.Column(db.Integer, default=3600)  # Execution timeout in seconds
    requires_elevation = db.Column(db.Boolean, default=False)  # Requires admin/root
    version = db.Column(db.String(32), default='1.0.0')

    executions = db.relationship('ScriptExecution', backref='script')

class AgentInstallCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(64), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    max_uses = db.Column(db.Integer, default=1)
    used_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    group_id = db.Column(db.Integer, db.ForeignKey('device_group.id'))
    template = db.Column(db.String(32))  # basic, advanced, network, security
    platform = db.Column(db.String(32))  # windows, linux
    client_name = db.Column(db.String(128))  # Added for client tracking
    client_email = db.Column(db.String(128))  # Added for client notifications
    license_key = db.Column(db.String(64), unique=True)  # Added for license tracking
    revoked_at = db.Column(db.DateTime, nullable=True)  # Added for license revocation
    revoked_reason = db.Column(db.String(256))  # Added to track revocation reason

    # Template configuration
    monitor_services = db.Column(db.Boolean, default=False)
    monitored_services = db.Column(db.Text)  # JSON list of service names
    monitor_logs = db.Column(db.Boolean, default=False)
    log_paths = db.Column(db.Text)  # JSON list of log file paths
    monitor_disk = db.Column(db.Boolean, default=False)
    disk_paths = db.Column(db.Text)  # JSON list of disk paths to monitor
    custom_checks = db.Column(db.Text)  # JSON configuration for custom monitoring

    def get_config(self):
        """Get the full monitoring configuration for this template"""
        config = {
            'monitor_services': self.monitor_services,
            'monitored_services': json.loads(self.monitored_services) if self.monitored_services else [],
            'monitor_logs': self.monitor_logs,
            'log_paths': json.loads(self.log_paths) if self.log_paths else [],
            'monitor_disk': self.monitor_disk,
            'disk_paths': json.loads(self.disk_paths) if self.disk_paths else [],
            'custom_checks': json.loads(self.custom_checks) if self.custom_checks else {}
        }
        return json.dumps(config)

    def is_valid(self):
        """Check if the installation code is valid"""
        if not self.is_active or self.revoked_at:
            return False
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        if self.max_uses and self.used_count >= self.max_uses:
            return False
        return True

class ScriptExecution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    script_id = db.Column(db.Integer, db.ForeignKey('remote_script.id'))
    executed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    session_id = db.Column(db.Integer, db.ForeignKey('remote_session.id'))
    script_content = db.Column(db.Text)
    script_type = db.Column(db.String(32))
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    exit_code = db.Column(db.Integer)
    output = db.Column(db.Text)
    error_output = db.Column(db.Text)
    status = db.Column(db.String(32))  # pending, running, completed, failed

    executor = db.relationship('User', backref='script_executions')
    session = db.relationship('RemoteSession', backref='script_executions')

class RemoteSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    session_type = db.Column(db.String(32))  # terminal, file_transfer, screen_share
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    status = db.Column(db.String(32))  # active, ended, terminated
    connection_id = db.Column(db.String(64))  # WebSocket connection ID

    user = db.relationship('User', backref='remote_sessions')
    device = db.relationship('Device')

class BulkDeployment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scheduled_time = db.Column(db.DateTime, nullable=True)  # If null, execute immediately
    status = db.Column(db.String(32), default='pending')  # pending, in_progress, completed, failed
    deployment_type = db.Column(db.String(32))  # script, windows_update
    script_id = db.Column(db.Integer, db.ForeignKey('remote_script.id'), nullable=True)
    target_devices = db.Column(db.Text)  # JSON list of device IDs
    success_count = db.Column(db.Integer, default=0)
    failure_count = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.DateTime, nullable=True)

    creator = db.relationship('User', backref='bulk_deployments')
    script = db.relationship('RemoteScript', backref='bulk_deployments')

class DeploymentResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    deployment_id = db.Column(db.Integer, db.ForeignKey('bulk_deployment.id'))
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    status = db.Column(db.String(32))  # pending, success, failed
    executed_at = db.Column(db.DateTime, nullable=True)
    output = db.Column(db.Text)
    error_message = db.Column(db.Text)
    exit_code = db.Column(db.Integer)

    deployment = db.relationship('BulkDeployment', backref='results')
    device = db.relationship('Device')

class AlertRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    # Alert Conditions
    metric_type = db.Column(db.String(32))  # cpu, memory, disk, network, custom
    condition = db.Column(db.String(32))  # above, below, equals
    threshold = db.Column(db.Float)
    duration = db.Column(db.Integer)  # Duration in seconds before alert triggers

    # Alert Settings
    severity = db.Column(db.String(32))  # info, warning, critical
    notification_channels = db.Column(db.String(256))  # JSON list of channels (email, dashboard, webhook)
    cooldown_period = db.Column(db.Integer)  # Minutes between repeated alerts

    # Target Devices/Groups
    target_type = db.Column(db.String(32))  # device, group, all
    target_id = db.Column(db.Integer)  # Device or group ID if specific target

    # Custom Check Configuration
    custom_check_type = db.Column(db.String(32))  # script, service, process, log
    custom_check_config = db.Column(db.Text)  # JSON configuration for custom check

    # Relationships
    creator = db.relationship('User', backref='alert_rules')
    history = db.relationship('AlertHistory', backref='rule', cascade='all, delete-orphan')

class AlertHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('alert_rule.id'))
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    triggered_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    status = db.Column(db.String(32))  # triggered, acknowledged, resolved
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    metric_value = db.Column(db.Float)
    details = db.Column(db.Text)  # Additional context about the alert

    # Relationships
    device = db.relationship('Device', backref='alert_history')
    acknowledger = db.relationship('User', backref='acknowledged_alerts')

class MonitoringProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Monitoring Settings
    metrics_interval = db.Column(db.Integer, default=60)  # Seconds between metric collections
    metrics_retention = db.Column(db.Integer, default=30)  # Days to keep metrics

    # Feature Toggles
    monitor_services = db.Column(db.Boolean, default=True)
    monitor_processes = db.Column(db.Boolean, default=True)
    monitor_logs = db.Column(db.Boolean, default=True)
    monitor_network = db.Column(db.Boolean, default=True)

    # Configuration
    watched_services = db.Column(db.Text)  # JSON list of service names
    watched_processes = db.Column(db.Text)  # JSON list of process patterns
    log_paths = db.Column(db.Text)  # JSON list of log file paths
    network_interfaces = db.Column(db.Text)  # JSON list of network interfaces

    # Custom Checks
    custom_checks = db.Column(db.Text)  # JSON configuration for custom monitoring

    # Relationships
    creator = db.relationship('User', backref='monitoring_profiles')
    devices = db.relationship('Device', backref='monitoring_profile', lazy='dynamic')

class NotificationChannel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    channel_type = db.Column(db.String(32))  # email, webhook, slack, teams
    configuration = db.Column(db.Text)  # JSON configuration for the channel
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    # Notification Preferences
    notify_on_severity = db.Column(db.String(32))  # all, warning_up, critical_only
    quiet_hours_start = db.Column(db.Time)
    quiet_hours_end = db.Column(db.Time)

    # Rate Limiting
    rate_limit = db.Column(db.Integer)  # Max notifications per hour
    rate_limit_reset = db.Column(db.DateTime)
    current_count = db.Column(db.Integer, default=0)

    # Relationships
    creator = db.relationship('User', backref='notification_channels')

class ShellSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    command_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(32), default='active')  # active, ended, terminated
    session_type = db.Column(db.String(32), default='shell')  # shell, sftp, remote_control
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    exit_code = db.Column(db.Integer, nullable=True)

    # Define relationships
    device = db.relationship('Device', backref='shell_sessions')
    user = db.relationship('User', backref='shell_sessions')

    def __repr__(self):
        return f'<ShellSession {self.id} - Device: {self.device_id} User: {self.user_id}>'

class FileTransferSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(32))  # active, completed, failed, terminated
    transfer_type = db.Column(db.String(32))  # upload, download
    source_path = db.Column(db.String(512))
    destination_path = db.Column(db.String(512))
    file_size = db.Column(db.BigInteger)
    bytes_transferred = db.Column(db.BigInteger, default=0)
    error_message = db.Column(db.Text)

    # Relationships
    device = db.relationship('Device', backref='file_transfers')
    user = db.relationship('User', backref='file_transfers')

class FileAuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action = db.Column(db.String(32))  # create, modify, delete, rename, move
    file_path = db.Column(db.String(512))
    previous_path = db.Column(db.String(512))  # For move/rename operations
    file_hash = db.Column(db.String(64))  # SHA-256 hash for integrity checks
    file_size = db.Column(db.BigInteger)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)

    # Relationships
    device = db.relationship('Device', backref='file_audit_logs')
    user = db.relationship('User', backref='file_audit_logs')

class FileMonitoringRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    path = db.Column(db.String(512))
    recursive = db.Column(db.Boolean, default=False)
    watch_create = db.Column(db.Boolean, default=True)
    watch_modify = db.Column(db.Boolean, default=True)
    watch_delete = db.Column(db.Boolean, default=True)
    watch_move = db.Column(db.Boolean, default=True)
    file_pattern = db.Column(db.String(128))  # Glob pattern for matching files
    ignore_pattern = db.Column(db.String(128))  # Glob pattern for ignoring files
    alert_on_change = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    device = db.relationship('Device', backref='file_monitoring_rules')
    creator = db.relationship('User', backref='file_monitoring_rules')