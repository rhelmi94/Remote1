from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from datetime import datetime
import json
from app import db
from models import BulkDeployment, DeploymentResult, Device, RemoteScript
from functools import wraps

bulk_bp = Blueprint('bulk_bp', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    return decorated_function

@bulk_bp.route('/api/deployments', methods=['POST'])
@login_required
@admin_required
def create_deployment():
    """Create a new bulk deployment"""
    try:
        data = request.get_json()
        
        # Validate input
        if not data.get('name'):
            return jsonify({'error': 'Deployment name is required'}), 400
            
        if not data.get('target_devices'):
            return jsonify({'error': 'No target devices selected'}), 400
            
        # Create deployment
        deployment = BulkDeployment(
            name=data['name'],
            description=data.get('description'),
            created_by=current_user.id,
            deployment_type=data['deployment_type'],
            script_id=data.get('script_id'),
            target_devices=json.dumps(data['target_devices']),
            scheduled_time=datetime.fromisoformat(data['scheduled_time']) if data.get('scheduled_time') else None
        )
        
        db.session.add(deployment)
        
        # Create result entries for each device
        for device_id in data['target_devices']:
            result = DeploymentResult(
                deployment_id=deployment.id,
                device_id=device_id,
                status='pending'
            )
            db.session.add(result)
            
        db.session.commit()
        
        return jsonify({
            'id': deployment.id,
            'status': 'created'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bulk_bp.route('/api/deployments/<int:deployment_id>/results')
@login_required
@admin_required
def get_deployment_results(deployment_id):
    """Get results for a specific deployment"""
    try:
        results = DeploymentResult.query.filter_by(deployment_id=deployment_id).all()
        
        return jsonify({
            'results': [{
                'device_name': result.device.name,
                'status': result.status,
                'executed_at': result.executed_at.isoformat() if result.executed_at else None,
                'output': result.output,
                'error_message': result.error_message,
                'exit_code': result.exit_code
            } for result in results]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@bulk_bp.route('/api/deployments/<int:deployment_id>/cancel', methods=['POST'])
@login_required
@admin_required
def cancel_deployment(deployment_id):
    """Cancel a pending deployment"""
    try:
        deployment = BulkDeployment.query.get_or_404(deployment_id)
        
        if deployment.status != 'pending':
            return jsonify({'error': 'Only pending deployments can be canceled'}), 400
            
        deployment.status = 'canceled'
        deployment.completed_at = datetime.utcnow()
        
        # Update all pending results to canceled
        DeploymentResult.query.filter_by(
            deployment_id=deployment_id,
            status='pending'
        ).update({'status': 'canceled'})
        
        db.session.commit()
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
