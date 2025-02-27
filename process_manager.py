import psutil
import json
from datetime import datetime
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from models import db, Device, SystemMetric

process_bp = Blueprint('process_bp', __name__)

def get_process_info(proc):
    """Get detailed information about a process"""
    try:
        with proc.oneshot():
            # Get process memory info
            mem_info = proc.memory_info()
            # Get process CPU times
            cpu_times = proc.cpu_times()
            # Get process connections
            connections = []
            try:
                for conn in proc.connections():
                    connections.append({
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': str(conn.laddr) if conn.laddr else None,
                        'raddr': str(conn.raddr) if conn.raddr else None,
                        'status': conn.status
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            return {
                'pid': proc.pid,
                'name': proc.name(),
                'status': proc.status(),
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent(),
                'create_time': datetime.fromtimestamp(proc.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                'username': proc.username(),
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'num_threads': proc.num_threads(),
                'memory_info': {
                    'rss': mem_info.rss,
                    'vms': mem_info.vms,
                    'shared': getattr(mem_info, 'shared', 0),
                    'text': getattr(mem_info, 'text', 0),
                    'data': getattr(mem_info, 'data', 0)
                },
                'cpu_times': {
                    'user': cpu_times.user,
                    'system': cpu_times.system,
                    'children_user': getattr(cpu_times, 'children_user', 0),
                    'children_system': getattr(cpu_times, 'children_system', 0)
                },
                'connections': connections,
                'num_fds': proc.num_fds() if hasattr(proc, 'num_fds') else None,
                'nice': proc.nice(),
                'ppid': proc.ppid(),
                'io_counters': proc.io_counters()._asdict() if hasattr(proc, 'io_counters') else None,
                'num_ctx_switches': proc.num_ctx_switches()._asdict() if hasattr(proc, 'num_ctx_switches') else None
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

@process_bp.route('/api/processes')
@login_required
def get_processes():
    """Get list of all running processes with details"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            proc_info = get_process_info(proc)
            if proc_info:
                processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return jsonify(processes)

@process_bp.route('/api/processes/<int:pid>')
@login_required
def get_process(pid):
    """Get detailed information about a specific process"""
    try:
        proc = psutil.Process(pid)
        proc_info = get_process_info(proc)
        if proc_info:
            return jsonify(proc_info)
        return jsonify({'error': 'Process not found'}), 404
    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process not found'}), 404
    except psutil.AccessDenied:
        return jsonify({'error': 'Access denied'}), 403

@process_bp.route('/api/processes/<int:pid>/terminate', methods=['POST'])
@login_required
def terminate_process(pid):
    """Terminate a specific process"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        proc = psutil.Process(pid)
        proc.terminate()
        return jsonify({'success': True, 'message': f'Process {pid} terminated'})
    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process not found'}), 404
    except psutil.AccessDenied:
        return jsonify({'error': 'Access denied'}), 403

@process_bp.route('/api/processes/<int:pid>/kill', methods=['POST'])
@login_required
def kill_process(pid):
    """Force kill a specific process"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        proc = psutil.Process(pid)
        proc.kill()
        return jsonify({'success': True, 'message': f'Process {pid} killed'})
    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process not found'}), 404
    except psutil.AccessDenied:
        return jsonify({'error': 'Access denied'}), 403

@process_bp.route('/api/processes/<int:pid>/suspend', methods=['POST'])
@login_required
def suspend_process(pid):
    """Suspend a specific process"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        proc = psutil.Process(pid)
        proc.suspend()
        return jsonify({'success': True, 'message': f'Process {pid} suspended'})
    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process not found'}), 404
    except psutil.AccessDenied:
        return jsonify({'error': 'Access denied'}), 403

@process_bp.route('/api/processes/<int:pid>/resume', methods=['POST'])
@login_required
def resume_process(pid):
    """Resume a suspended process"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        proc = psutil.Process(pid)
        proc.resume()
        return jsonify({'success': True, 'message': f'Process {pid} resumed'})
    except psutil.NoSuchProcess:
        return jsonify({'error': 'Process not found'}), 404
    except psutil.AccessDenied:
        return jsonify({'error': 'Access denied'}), 403

@process_bp.route('/api/processes/metrics')
@login_required
def get_system_metrics():
    """Get current system-wide metrics"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net_io = psutil.net_io_counters()

    return jsonify({
        'cpu_percent': cpu_percent,
        'memory': {
            'total': memory.total,
            'available': memory.available,
            'percent': memory.percent,
            'used': memory.used,
            'free': memory.free
        },
        'disk': {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent
        },
        'network': {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
    })