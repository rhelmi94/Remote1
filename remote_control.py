from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from models import (
    Device, RemoteScript, ScriptExecution, RemoteSession,
    db
)
from datetime import datetime
import os
import json

remote_bp = Blueprint('remote_bp', __name__)

@remote_bp.route('/api/remote/sessions/start', methods=['POST'])
@login_required
def start_remote_session():
    """Start a new remote control session"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        session_type = data.get('session_type')  # powershell, cmd, terminal
        
        device = Device.query.get_or_404(device_id)
        
        # Check if device is online
        if not device.is_online:
            return jsonify({'error': 'Device is offline'}), 400
            
        # Create new session
        session = RemoteSession(
            device_id=device_id,
            user_id=current_user.id,
            session_type=session_type,
            status='active'
        )
        
        db.session.add(session)
        db.session.commit()
        
        return jsonify({
            'session_id': session.id,
            'status': 'active',
            'start_time': session.start_time.isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/api/remote/sessions/<int:session_id>/end', methods=['POST'])
@login_required
def end_remote_session(session_id):
    """End a remote control session"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        session = RemoteSession.query.get_or_404(session_id)
        
        if session.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        session.status = 'ended'
        session.end_time = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/api/remote/execute', methods=['POST'])
@login_required
def execute_command():
    """Execute a command on a remote device"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        command = data.get('command')
        session_id = data.get('session_id')
        
        session = RemoteSession.query.get_or_404(session_id)
        
        if session.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        if session.status != 'active':
            return jsonify({'error': 'Session is not active'}), 400
            
        # Here we'll send the command to the agent
        # This will be implemented in the agent code
        
        return jsonify({
            'status': 'success',
            'command': command,
            'timestamp': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@remote_bp.route('/api/scripts', methods=['GET', 'POST'])
@login_required
def manage_scripts():
    """Manage remote scripts"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    if request.method == 'GET':
        scripts = RemoteScript.query.filter_by(created_by=current_user.id).all()
        return jsonify([{
            'id': script.id,
            'name': script.name,
            'description': script.description,
            'script_type': script.script_type,
            'target_platform': script.target_platform,
            'created_at': script.created_at.isoformat()
        } for script in scripts])
        
    else:  # POST
        try:
            data = request.get_json()
            script = RemoteScript(
                name=data['name'],
                description=data.get('description'),
                script_type=data['script_type'],
                content=data['content'],
                created_by=current_user.id,
                target_platform=data['target_platform']
            )
            
            db.session.add(script)
            db.session.commit()
            
            return jsonify({
                'id': script.id,
                'status': 'created'
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@remote_bp.route('/api/scripts/<int:script_id>/execute', methods=['POST'])
@login_required
def execute_script(script_id):
    """Execute a script on a remote device"""
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        
        script = RemoteScript.query.get_or_404(script_id)
        device = Device.query.get_or_404(device_id)
        
        if script.created_by != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        if not device.is_online:
            return jsonify({'error': 'Device is offline'}), 400
            
        # Create execution record
        execution = ScriptExecution(
            script_id=script_id,
            device_id=device_id,
            executed_by=current_user.id,
            status='pending'
        )
        
        db.session.add(execution)
        db.session.commit()
        
        # Here we'll send the script to the agent
        # This will be implemented in the agent code
        
        return jsonify({
            'execution_id': execution.id,
            'status': 'pending'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
