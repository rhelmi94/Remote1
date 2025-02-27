import psutil
import platform
from flask import Blueprint, jsonify, render_template, request, send_file
from flask_login import login_required, current_user
from models import SystemMetric, Device, DeviceGroup, DeviceSession, AgentInstallCode, BulkDeployment, RemoteSession # Added imports for new models
from app import db
import socket
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timedelta
import os
import io
import zipfile
import tarfile
import json
from werkzeug.utils import secure_filename
import secrets
import logging
import sys
import subprocess

logger = logging.getLogger(__name__)

monitor_bp = Blueprint('monitor_bp', __name__)

# Add datetime filter for templates
@monitor_bp.app_template_filter('datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a datetime object for display"""
    if value is None:
        return ""
    return value.strftime(format)

def get_system_info():
    """Get detailed system information"""
    try:
        return {
            'platform': platform.system(),
            'os_version': platform.version(),
            'cpu_model': platform.processor(),
            'total_memory': psutil.virtual_memory().total,
            'total_storage': psutil.disk_usage('/').total,
            'process_count': len(psutil.pids()),
            'temperature': psutil.sensors_temperatures().get('coretemp', [{'current': None}])[0]['current']
        }
    except Exception as e:
        return {'error': str(e)}

def check_connection_health(ip, port):
    """Check connection health with enhanced metrics"""
    try:
        start_time = time.time()
        with socket.create_connection((ip, port), timeout=2) as sock:
            latency = (time.time() - start_time) * 1000  # Convert to milliseconds

            # Multiple connection attempts for jitter calculation
            latencies = []
            for _ in range(3):
                start = time.time()
                sock.send(b'ping')
                sock.recv(4)
                latencies.append((time.time() - start) * 1000)

            avg_latency = sum(latencies) / len(latencies)
            jitter = max(latencies) - min(latencies)

            return {
                'status': 'healthy' if avg_latency < 100 else 'warning' if avg_latency < 300 else 'poor',
                'latency': round(avg_latency, 2),
                'jitter': round(jitter, 2),
                'packet_loss': 0  # Can be implemented with actual packet loss tracking
            }
    except (socket.timeout, socket.error):
        return {'status': 'error', 'latency': None, 'jitter': None, 'packet_loss': 100}

def get_system_metrics():
    """Get comprehensive system metrics"""
    network = psutil.net_io_counters()
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_percent': psutil.disk_usage('/').percent,
        'network': {
            'bytes_sent': network.bytes_sent,
            'bytes_recv': network.bytes_recv,
            'packets_sent': network.packets_sent,
            'packets_recv': network.packets_recv,
            'error_in': network.errin,
            'error_out': network.errout,
            'drop_in': network.dropin,
            'drop_out': network.dropout
        },
        'process_count': len(psutil.pids()),
        'temperature': psutil.sensors_temperatures().get('coretemp', [{'current': None}])[0]['current']
    }

def get_network_connections():
    """Get detailed network connections with device information"""
    connections = []
    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    remote_ip = conn.raddr.ip if conn.raddr else None
                    remote_port = conn.raddr.port if conn.raddr else None

                    if remote_ip and remote_port:
                        # Skip loopback and internal test addresses
                        if remote_ip.startswith('127.') or remote_ip in ['0.0.0.0', '172.31.128.48']:
                            continue

                        device = Device.query.filter_by(ip_address=remote_ip).first()
                        health = check_connection_health(remote_ip, remote_port)

                        if device:
                            # Update existing device
                            device.last_seen = datetime.utcnow()
                            device.status = health['status']
                            device.latency = health['latency']
                            device.is_online = True
                            db.session.commit()

                        connection_info = {
                            'device_id': device.id if device else None,
                            'name': device.name if device else f"Unknown Device ({remote_ip})",
                            'local_ip': conn.laddr.ip,
                            'local_port': conn.laddr.port,
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'platform': device.platform if device else None,
                            'os_version': device.os_version if device else None,
                            'status': health['status'],
                            'latency': health['latency'],
                            'jitter': health.get('jitter'),
                            'packet_loss': health.get('packet_loss'),
                            'group_id': device.group_id if device else None,
                            'group_name': device.group.name if device and device.group_id else None,
                            'last_seen': device.last_seen.isoformat() if device else None
                        }
                        connections.append(connection_info)

    except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
        logger.error(f"Error accessing process information: {e}")
    return connections

@monitor_bp.route('/dashboard')
@login_required
def dashboard():
    """Render dashboard with device health information"""
    try:
        groups = DeviceGroup.query.all()
        devices = Device.query.all()
        active_sessions = DeviceSession.query.filter_by(
            user_id=current_user.id,
            status='active'
        ).all()

        # Get the selected device if specified
        selected_device_id = request.args.get('device_id', type=int)
        selected_device = None
        if selected_device_id:
            selected_device = Device.query.get(selected_device_id)
        elif devices:
            selected_device = devices[0]  # Default to first device if none selected

        # Get active installation codes for admin users
        install_codes = []
        if current_user.is_admin:
            install_codes = AgentInstallCode.query.filter_by(is_active=True)\
                .order_by(AgentInstallCode.created_at.desc())\
                .all()

        return render_template('dashboard.html',
                            groups=groups,
                            devices=devices,
                            selected_device=selected_device,
                            install_codes=install_codes,
                            active_sessions=active_sessions)
    except Exception as e:
        print(f"Dashboard error: {e}")  # Debug logging
        return render_template('dashboard.html', error=str(e))

@monitor_bp.route('/api/metrics', methods=['GET', 'POST'])
@login_required
def metrics():
    """Handle metrics endpoints for both retrieving and receiving metrics"""
    if request.method == 'GET':
        metrics = get_system_metrics()
        system_metric = SystemMetric(
            cpu_percent=metrics['cpu_percent'],
            memory_percent=metrics['memory_percent'],
            disk_percent=metrics['disk_percent'],
            network_in_bytes=metrics['network']['bytes_recv'],
            network_out_bytes=metrics['network']['bytes_sent'],
            process_count=metrics['process_count'],
            temperature=metrics['temperature']
        )
        db.session.add(system_metric)
        db.session.commit()
        return jsonify(metrics)
    else:  # POST
        try:
            data = request.get_json()
            device_id = data.get('device_id')
            device = Device.query.get_or_404(device_id)

            # Update device health status
            device.health_score = data.get('health_score', 100)
            device.performance_rating = data.get('performance_rating', 5.0)
            device.cpu_health = data.get('cpu_health', 'normal')
            device.memory_health = data.get('memory_health', 'normal')
            device.disk_health = data.get('disk_health', 'normal')
            device.network_health = data.get('network_health', 'normal')
            device.last_health_check = datetime.utcnow()
            device.is_online = True

            # Create new system metric
            metric = SystemMetric(
                device_id=device_id,
                cpu_percent=data.get('cpu_percent'),
                memory_percent=data.get('memory_percent'),
                disk_percent=data.get('disk_percent'),
                network_in_bytes=data.get('network', {}).get('bytes_recv'),
                network_out_bytes=data.get('network', {}).get('bytes_sent'),
                process_count=data.get('process_count'),
                temperature=data.get('temperature')
            )
            db.session.add(metric)
            db.session.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/network-connections')
@login_required
def network_connections():
    group_id = request.args.get('group_id', type=int)
    connections = get_network_connections()
    if group_id:
        connections = [conn for conn in connections if conn['group_id'] == group_id]
    return jsonify(connections)

@monitor_bp.route('/api/groups', methods=['GET', 'POST'])
@login_required
def manage_groups():
    """Handle group management"""
    if request.method == 'POST':
        try:
            data = request.get_json()
            if not data.get('name'):
                return jsonify({'error': 'Group name is required'}), 400

            group = DeviceGroup(
                name=data['name'],
                description=data.get('description', '')
            )
            db.session.add(group)
            db.session.commit()

            return jsonify({
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'device_count': 0
            })
        except Exception as e:
            logger.error(f"Error creating group: {e}")
            return jsonify({'error': str(e)}), 500

    # GET request - return all groups
    groups = DeviceGroup.query.all()
    return jsonify([{
        'id': group.id,
        'name': group.name,
        'description': group.description,
        'device_count': len(group.devices)
    } for group in groups])

@monitor_bp.route('/api/groups/<int:group_id>/devices', methods=['POST'])
@login_required
def add_device_to_group(group_id):
    data = request.get_json()
    device = Device.query.get_or_404(data['device_id'])
    device.group_id = group_id
    db.session.commit()
    return jsonify({'success': True})

@monitor_bp.route('/api/groups/<int:group_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_group(group_id):
    group = DeviceGroup.query.get_or_404(group_id)

    if request.method == 'PUT':
        data = request.get_json()
        group.name = data.get('name', group.name)
        group.description = data.get('description', group.description)
        db.session.commit()
        return jsonify({'success': True})

    elif request.method == 'DELETE':
        # Update devices to remove group association
        Device.query.filter_by(group_id=group_id).update({'group_id': None})
        db.session.delete(group)
        db.session.commit()
        return jsonify({'success': True})

    return jsonify({'error': 'Method not allowed'}), 405


@monitor_bp.route('/api/devices', methods=['POST'])
@login_required
def create_device():
    """Create a new device configuration"""
    try:
        data = request.get_json()
        print("Received data:", data)  # Debug log

        name = data.get('name')
        group_id = data.get('group_id')
        platform = data.get('platform')

        if not name or not platform:
            return jsonify({'error': 'Name and platform are required'}), 400

        # Initialize device with all required fields
        device = Device(
            name=name,
            group_id=group_id if group_id else None,
            platform=platform,
            is_online=False,
            status='offline',  # initial status
            agent_version='1.0.0',
            # Initial health metrics
            health_score=100,
            performance_rating=5.0,
            cpu_health='normal',
            memory_health='normal',
            disk_health='normal',
            network_health='normal',
            last_health_check=datetime.utcnow(),
            # System metrics
            cpu_usage=0.0,
            memory_usage=0.0,
            disk_usage=0.0,
            network_in_rate=0.0,
            network_out_rate=0.0,
            process_count=0,
            uptime=0,
            temperature=None
        )

        db.session.add(device)
        db.session.commit()

        return jsonify({
            'success': True,
            'device': {
                'id': device.id,
                'name': device.name,
                'platform': device.platform,
                'status': device.status,
                'health_score': device.health_score
            }
        })
    except Exception as e:
        logger.error(f"Error creating device: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/devices/<int:device_id>', methods=['DELETE'])
@login_required
def delete_device(device_id):
    """Delete a device"""
    try:
        device = Device.query.get_or_404(device_id)
        # Delete associated metrics first
        SystemMetric.query.filter_by(device_id=device.id).delete()
        db.session.delete(device)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting device: {e}")
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/register', methods=['POST'])
def register_device():
    """Register a new monitoring agent"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        required_fields = ['platform', 'os_version', 'cpu_model', 'total_memory', 'total_storage']
        missing_fields = [field for field in required_fields if not data.get(field)]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

        # Validate install code if provided
        install_code = data.get('install_code')
        if install_code:
            code_obj = AgentInstallCode.query.filter_by(code=install_code, is_active=True).first()
            if not code_obj:
                return jsonify({'error': 'Invalid or inactive installation code'}), 400
            if code_obj.expires_at and code_obj.expires_at < datetime.utcnow():
                return jsonify({'error': 'Installation code has expired'}), 400

        # Get device hostname or generate a unique name
        hostname = data.get('hostname', '')
        device_name = hostname if hostname else f"Device-{secrets.token_hex(4)}"

        # Create or update device
        device = Device.query.filter_by(ip_address=request.remote_addr).first()
        if device:
            # Update existing device
            device.name = device_name
            device.platform = data['platform']
            device.os_version = data['os_version']
            device.cpu_model = data['cpu_model']
            device.total_memory = data['total_memory']
            device.total_storage = data['total_storage']
            device.agent_version = data.get('agent_version')
            device.last_seen = datetime.utcnow()
            device.is_online = True
        else:
            # Create new device
            device = Device(
                name=device_name,
                ip_address=request.remote_addr,
                platform=data['platform'],
                os_version=data['os_version'],
                cpu_model=data['cpu_model'],
                total_memory=data['total_memory'],
                total_storage=data['total_storage'],
                agent_version=data.get('agent_version'),
                is_online=True,
                group_id=code_obj.group_id if install_code and code_obj else None
            )
            db.session.add(device)

        # Update install code usage if provided
        if install_code and code_obj:
            code_obj.used_count += 1
            if code_obj.max_uses and code_obj.used_count >= code_obj.max_uses:
                code_obj.is_active = False

        db.session.commit()

        return jsonify({
            'device_id': device.id,
            'status': 'registered',
            'name': device.name
        })
    except Exception as e:
        logger.error(f"Device registration error: {e}")
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/install-codes', methods=['POST'])
@login_required
def create_install_code():
    """Create a new installation code for agents"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.get_json()
        code = secrets.token_urlsafe(32)
        license_key = secrets.token_urlsafe(32)

        # Convert expires_in to integer before creating timedelta
        try:
            expires_in = int(data.get('expires_in', 24))  # hours
        except (TypeError, ValueError):
            expires_in = 24  # default to 24 hours if invalid input

        install_code = AgentInstallCode(
            code=code,
            created_by=current_user.id,
            expires_at=datetime.utcnow() + timedelta(hours=expires_in),
            max_uses=int(data.get('max_uses', 1)),
            group_id=data.get('group_id'),
            template=data.get('template', 'basic'),
            platform=data.get('platform', 'linux'),
            client_name=data.get('client_name'),
            client_email=data.get('client_email'),
            license_key=license_key,
            # Add monitoring configuration
            monitor_services=data.get('monitor_services', False),
            monitored_services=json.dumps(data.get('monitored_services', [])),
            monitor_logs=data.get('monitor_logs', False),
            log_paths=json.dumps(data.get('log_paths', [])),
            monitor_disk=data.get('monitor_disk', False),
            disk_paths=json.dumps(data.get('disk_paths', [])),
            custom_checks=json.dumps(data.get('custom_checks', {}))
        )

        db.session.add(install_code)
        db.session.commit()

        return jsonify({
            'code': code,
            'license_key': license_key,
            'expires_at': install_code.expires_at.isoformat(),
            'max_uses': install_code.max_uses,
            'client_name': install_code.client_name
        })
    except Exception as e:
        logger.error(f"Error creating install code: {e}")
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/install-codes/<code>/revoke', methods=['POST'])
@login_required
def revoke_install_code(code):
    """Revoke an installation code"""
    try:
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403

        install_code = AgentInstallCode.query.filter_by(code=code).first()
        if not install_code:
            return jsonify({'error': 'Invalid installation code'}), 404

        data = request.get_json()
        install_code.is_active = False
        install_code.revoked_at = datetime.utcnow()
        install_code.revoked_reason = data.get('reason', 'Manually revoked by administrator')

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Installation code successfully revoked'
        })
    except Exception as e:
        logger.error(f"Error revoking install code: {e}")
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/install-codes/<code>/verify', methods=['GET'])
def verify_install_code(code):
    """Verify an installation code and return configuration"""
    try:
        install_code = AgentInstallCode.query.filter_by(code=code).first()

        if not install_code:
            return jsonify({'error': 'Invalid installation code'}), 404

        if not install_code.is_valid():
            return jsonify({'error': 'Installation code is no longer valid'}), 400

        # Increment used count
        install_code.used_count += 1
        if install_code.max_uses and install_code.used_count >= install_code.max_uses:
            install_code.is_active = False

        db.session.commit()

        return jsonify({
            'valid': True,
            'config': {
                'server_url': request.host_url.rstrip('/'),
                'group_id': install_code.group_id,
                'template': install_code.template,
                'platform': install_code.platform,
                'license_key': install_code.license_key,
                'monitoring': json.loads(install_code.get_config())
            }
        })
    except Exception as e:
        logger.error(f"Error verifying install code: {e}")
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/install/<code>')
def install_agent_with_code(code):
    """Install page for agent installation with code"""
    install_code = AgentInstallCode.query.filter_by(code=code).first()
    if not install_code or not install_code.is_valid():
        return 'Invalid or expired installation code', 404

    return render_template('install.html', 
                         install_code=install_code,
                         server_url=request.host_url.rstrip('/'))

@monitor_bp.route('/download-agent/<platform>')
@login_required
def download_agent(platform):
    """Generate and download the agent package for the specified platform"""
    try:
        if platform not in ['windows', 'linux']:
            return 'Invalid platform', 400

        # Prepare configuration
        config = {
            'server_url': request.host_url.rstrip('/')
        }

        memory_file = io.BytesIO()

        if platform == 'windows':
            with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Add Python script files
                zf.write('agent/agent.py', 'agent.py')
                zf.write('agent/install.bat', 'install.bat')

                # Add configuration
                zf.writestr('config.json', json.dumps(config, indent=2))

                # Add readme with installation instructions
                readme = """
Windows Agent Installation Instructions:
1. Extract all files from this zip
2. Make sure Python 3.8 or later is installed
3. Run install.bat as administrator
4. The agent will start automatically and run on startup
"""
                zf.writestr('README.txt', readme)

            memory_file.seek(0)
            return send_file(
                memory_file,
                mimetype='application/zip',
                as_attachment=True,
                download_name='remote_monitor_agent_windows.zip'
            )
        else:
            # Linux package
            with tarfile.open(fileobj=memory_file, mode='w:gz') as tar:
                # Add Python files
                for file_path in ['agent/agent.py', 'agent/install.sh']:
                    tar.add(file_path, arcname=os.path.basename(file_path))

                # Add configuration
                config_file = io.BytesIO(json.dumps(config, indent=2).encode())
                config_info = tarfile.TarInfo(name='config.json')
                config_info.size = len(config_file.getvalue())
                config_file.seek(0)
                tar.addfile(config_info, config_file)

            memory_file.seek(0)
            return send_file(
                memory_file,
                mimetype='application/gzip',
                as_attachment=True,
                download_name='remote_monitor_agent_linux.tar.gz'
            )
    except Exception as e:
        logger.error("Error generating agent package: %s", str(e), exc_info=True)
        return f"Error generating agent package: {str(e)}", 500

@monitor_bp.route('/api/metrics/remote-control/<int:device_id>', methods=['POST'])
@login_required
def remote_control_metrics(device_id):
    """Handle remote control metrics updates"""
    try:
        data = request.get_json()
        device = Device.query.get_or_404(device_id)

        # Update device metrics
        device.cpu_usage = data.get('cpu_usage')
        device.memory_usage = data.get('memory_usage')
        device.disk_usage = data.get('disk_usage')
        device.network_in_rate = data.get('network_in_rate')
        device.network_out_rate = data.get('network_out_rate')
        device.process_count = data.get('process_count')
        device.uptime = data.get('uptime')
        device.temperature = data.get('temperature')

        # Update health status
        device.cpu_health = data.get('cpu_health', 'normal')
        device.memory_health = data.get('memory_health', 'normal')
        device.disk_health = data.get('disk_health', 'normal')
        device.network_health = data.get('network_health', 'normal')

        device.update_health_score() # Assuming update_health_score is defined in Device model
        device.update_status() # Assuming update_status is defined in Device model
        device.last_seen = datetime.utcnow()

        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating remote control metrics: {e}")
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/device/<int:device_id>/settings', methods=['GET', 'POST'])
@login_required
def device_settings(device_id):
    """Handle device settings"""
    device = Device.query.get_or_404(device_id)

    if request.method == 'POST':
        try:
            data = request.get_json()
            device.name = data.get('name', device.name)
            device.group_id = data.get('group_id', device.group_id)
            device.notes = data.get('notes', device.notes)
            device.template = data.get('template', device.template)

            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            logger.error(f"Error updating device settings: {e}")
            return jsonify({'error': str(e)}), 500

    return jsonify({
        'name': device.name,
        'group_id': device.group_id,
        'notes': device.notes,
        'template': device.template
    })

@monitor_bp.route('/api/device/<int:device_id>/bulk-deploy', methods=['POST'])
@login_required
def bulk_deploy(device_id):
    """Handle bulk deployment to device"""
    try:
        data = request.get_json()
        deployment = BulkDeployment(
            name=data['name'],
            description=data.get('description'),
            created_by=current_user.id,
            deployment_type=data['type'],
            script_id=data.get('script_id'),
            target_devices=json.dumps([device_id]),
            scheduled_time=datetime.fromisoformat(data['scheduled_time']) if data.get('scheduled_time') else None
        )

        db.session.add(deployment)
        db.session.commit()

        return jsonify({
            'deployment_id': deployment.id,
            'status': 'scheduled' if deployment.scheduled_time else 'pending'
        })
    except Exception as e:
        logger.error(f"Error creating bulk deployment: {e}")
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/device/<int:device_id>/remote-sessions', methods=['POST'])
@login_required
def create_remote_session(device_id):
    """Create a new remote session"""
    try:
        data = request.get_json()
        session = RemoteSession(
            user_id=current_user.id,
            device_id=device_id,
            session_type=data['type'],
            status='active',
            connection_id=secrets.token_urlsafe(32)
        )

        db.session.add(session)
        db.session.commit()

        return jsonify({
            'session_id': session.id,
            'connection_id': session.connection_id
        })
    except Exception as e:
        logger.error(f"Error creating remote session: {e}")
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/device/<int:device_id>/remote-sessions/<int:session_id>', methods=['PUT'])
@login_required
def update_remote_session(device_id, session_id):
    """Update remote session status"""
    try:
        session = RemoteSession.query.get_or_404(session_id)
        if session.device_id != device_id or session.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.get_json()
        session.status = data['status']
        if data['status'] == 'ended':
            session.ended_at = datetime.utcnow()

        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error updating remote session: {e}")
        return jsonify({'error': str(e)}), 500

@monitor_bp.route('/api/device/<int:device_id>/health-report')
@login_required
def device_health_report(device_id):
    """Get detailed device health report"""
    try:
        device = Device.query.get_or_404(device_id)

        # Get recent metrics
        recent_metrics = SystemMetric.query.filter_by(device_id=device_id)\
            .order_by(SystemMetric.timestamp.desc())\
            .limit(100)\
            .all()

        metrics_data = [{
            'timestamp': metric.timestamp.isoformat(),
            'cpu_percent': metric.cpu_percent,
            'memory_percent': metric.memory_percent,
            'disk_percent': metric.disk_percent,
            'network_in': metric.network_in_bytes,
            'network_out': metric.networkout_bytes,
            'process_count': metric.process_count,
            'temperature': metric.temperature
        } for metric in recent_metrics]

        return jsonify({
            'device_name': device.name,
            'health_score': device.health_score,
            'performance_rating': device.performance_rating,
            'health_status': {
                'cpu': device.cpu_health,
                'memory': device.memory_health,
                'disk': device.disk_health,
                'network': device.network_health
            },
            'current_metrics': {
                'cpu_usage': device.cpu_usage,
                'memory_usage': device.memory_usage,
                'disk_usage': device.disk_usage,
                'network_in_rate': device.network_in_rate,
                'network_out_rate': device.network_out_rate,
                'process_count': device.process_count,
                'uptime': device.uptime,
                'temperature': device.temperature
            },
            'historical_metrics': metrics_data,
            'last_updated': device.last_health_check.isoformat()
        })
    except Exception as e:
        logger.error(f"Error generating health report: {e}")
        return jsonify({'error': str(e)}), 500