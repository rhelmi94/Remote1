from functools import wraps
from flask import request, jsonify, session, current_app
import pyotp
from flask_login import current_user
from models import ApiKey, AuditLog
from datetime import datetime

def require_2fa(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
            
        if current_user.two_factor_enabled:
            if not session.get('2fa_verified'):
                return jsonify({'error': '2FA verification required'}), 403
                
        return f(*args, **kwargs)
    return decorated_function

def validate_api_key():
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return None
        
    key = ApiKey.query.filter_by(key=api_key, is_active=True).first()
    if not key:
        return None
        
    if key.expires_at and key.expires_at < datetime.utcnow():
        key.is_active = False
        db.session.commit()
        return None
        
    key.last_used = datetime.utcnow()
    db.session.commit()
    return key

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        key = validate_api_key()
        if not key:
            return jsonify({'error': 'Valid API key required'}), 401
            
        return f(*args, **kwargs)
    return decorated_function

def log_audit(action, target_type=None, target_id=None, details=None):
    if current_user.is_authenticated:
        log = AuditLog(
            user_id=current_user.id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details=details,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(log)
        db.session.commit()

def generate_2fa_secret():
    return pyotp.random_base32()

def verify_2fa_token(secret, token):
    totp = pyotp.TOTP(secret)
    return totp.verify(token)
