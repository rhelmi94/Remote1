from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for
from flask_login import login_required, current_user
from models import User, db
from werkzeug.security import generate_password_hash
from datetime import datetime

admin_bp = Blueprint('admin_bp', __name__)

def admin_required(f):
    """Decorator to check if user is admin"""
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'error': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__  # Fix the endpoint conflict
    return decorated_function

@admin_bp.route('/admin/users')
@admin_required
def manage_users():
    """Admin user management interface"""
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/admin/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def manage_user(user_id):
    """Manage individual user"""
    user = User.query.get_or_404(user_id)

    if request.method == 'GET':
        return jsonify(user.to_dict())

    elif request.method == 'PUT':
        data = request.get_json()

        if 'username' in data:
            user.username = data['username']
        if 'email' in data:
            user.email = data['email']
        if 'phone_number' in data:
            user.phone_number = data['phone_number']
        if 'is_admin' in data:
            user.is_admin = data['is_admin']
        if 'password' in data:
            user.set_password(data['password'])

        db.session.commit()
        return jsonify({'status': 'success'})

    elif request.method == 'DELETE':
        if user.id == current_user.id:
            return jsonify({'error': 'Cannot delete yourself'}), 400
        db.session.delete(user)
        db.session.commit()
        return jsonify({'status': 'success'})

@admin_bp.route('/admin/users/reset-password/<int:user_id>', methods=['POST'])
@admin_required
def reset_user_password(user_id):
    """Reset user password"""
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    if 'new_password' not in data:
        return jsonify({'error': 'New password is required'}), 400

    user.set_password(data['new_password'])
    db.session.commit()

    return jsonify({'status': 'success'})