from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from models import User
from utils.email_handler import send_password_reset_email, generate_reset_token, verify_reset_token

auth_bp = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth_bp.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('monitor_bp.dashboard'))
    return redirect(url_for('auth.login'))

@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('monitor_bp.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('signup.html')

        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return render_template('signup.html')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already registered')
            return render_template('signup.html')

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please login.')
        return redirect(url_for('auth.login'))

    return render_template('signup.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('monitor_bp.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('monitor_bp.dashboard'))
        flash('Invalid username or password')

    return render_template('login.html')

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('monitor_bp.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_reset_token(email)
            reset_url = url_for('auth.reset_password', token=token, _external=True)
            send_password_reset_email(email, reset_url)
            flash('Password reset instructions have been sent to your email.')
        else:
            # We still show the same message to prevent email enumeration
            flash('Password reset instructions have been sent to your email.')

        return redirect(url_for('auth.login'))

    return render_template('forgot_password.html')

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('monitor_bp.dashboard'))

    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired reset token')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User not found')
            return redirect(url_for('auth.forgot_password'))

        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('reset_password.html')

        user.set_password(password)
        db.session.commit()
        flash('Your password has been reset! Please login.')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))