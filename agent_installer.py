import os
import uuid
import json
import shutil
import subprocess
from datetime import datetime
from flask import Blueprint, request, jsonify, send_file, current_app
from models import AgentInstallCode, Device
from app import db

agent_installer = Blueprint('agent_installer', __name__)

AGENT_FILES = [
    'agent/windows_agent.py',
    'agent/remote_control.py',
]

@agent_installer.route('/api/installer/validate-license', methods=['POST'])
def validate_license():
    """Validate a license key during agent installation"""
    data = request.get_json()
    license_key = data.get('license_key')

    if not license_key:
        return jsonify({'error': 'License key is required'}), 400

    install_code = AgentInstallCode.query.filter_by(license_key=license_key).first()

    if not install_code or not install_code.is_valid():
        return jsonify({'error': 'Invalid or expired license key'}), 403

    return jsonify({
        'valid': True,
        'template': install_code.template,
        'configuration': install_code.get_config()
    })

@agent_installer.route('/api/installer/register', methods=['POST'])
def register_agent():
    """Register a new device with a valid license key"""
    data = request.get_json()
    license_key = data.get('license_key')
    device_info = data.get('device_info', {})

    install_code = AgentInstallCode.query.filter_by(license_key=license_key).first()

    if not install_code or not install_code.is_valid():
        return jsonify({'error': 'Invalid or expired license key'}), 403

    try:
        # Create new device entry
        device = Device(
            name=device_info.get('hostname', 'Unknown Device'),
            ip_address=device_info.get('ip_address'),
            platform=device_info.get('platform'),
            os_version=device_info.get('os_version'),
            cpu_model=device_info.get('cpu_model'),
            total_memory=device_info.get('total_memory'),
            total_storage=device_info.get('total_storage'),
            agent_version=device_info.get('agent_version'),
            group_id=install_code.group_id,
            status='online',
            last_seen=datetime.utcnow()
        )

        # Update install code usage
        install_code.used_count += 1

        db.session.add(device)
        db.session.commit()

        return jsonify({
            'success': True,
            'device_id': device.id,
            'configuration': install_code.get_config()
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@agent_installer.route('/api/installer/generate/<license_key>', methods=['GET'])
def generate_installer(license_key):
    """Generate a customized installer package with embedded license key"""
    install_code = AgentInstallCode.query.filter_by(license_key=license_key).first()

    if not install_code or not install_code.is_valid():
        return jsonify({'error': 'Invalid or expired license key'}), 403

    try:
        # Generate a unique installer package with embedded license
        installer_path = create_installer_package(license_key, install_code.template)
        if installer_path and os.path.exists(installer_path):
            return send_file(
                installer_path,
                as_attachment=True,
                download_name=f'rmm_agent_setup_{license_key[:8]}.exe'
            )
        else:
            return jsonify({'error': 'Failed to generate installer'}), 500

    except Exception as e:
        current_app.logger.error(f"Installer generation error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def create_installer_package(license_key, template):
    """Create a customized installer package with embedded license key"""
    try:
        # Create temporary build directory
        build_dir = os.path.join(current_app.instance_path, 'build', str(uuid.uuid4()))
        os.makedirs(build_dir, exist_ok=True)

        # Copy agent files to build directory
        for file_path in AGENT_FILES:
            shutil.copy2(
                os.path.join(current_app.root_path, file_path),
                build_dir
            )

        # Create agent configuration
        config = {
            'license_key': license_key,
            'server_url': os.environ.get('SERVER_URL', 'http://localhost:5000'),
            'template': template
        }

        config_path = os.path.join(build_dir, 'config.json')
        with open(config_path, 'w') as f:
            json.dump(config, f)

        # Create PyInstaller spec file
        spec_content = f'''
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['{os.path.join(build_dir, "windows_agent.py")}'],
    pathex=['{build_dir}'],
    binaries=[],
    datas=[
        ('{config_path}', '.'),
        ('{os.path.join(build_dir, "remote_control.py")}', '.')
    ],
    hiddenimports=['win32timezone'],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='rmm_agent_setup',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version='1.0.0',
    uac_admin=True
)
'''

        spec_path = os.path.join(build_dir, 'agent.spec')
        with open(spec_path, 'w') as f:
            f.write(spec_content)

        # Run PyInstaller
        subprocess.run([
            'pyinstaller',
            '--clean',
            '--workpath', os.path.join(build_dir, 'build'),
            '--distpath', os.path.join(build_dir, 'dist'),
            spec_path
        ], check=True)

        # Return path to the generated executable
        exe_path = os.path.join(build_dir, 'dist', 'rmm_agent_setup.exe')
        if os.path.exists(exe_path):
            return exe_path
        else:
            raise Exception("Installer executable not found after build")

    except Exception as e:
        current_app.logger.error(f"Error creating installer package: {str(e)}")
        raise

    finally:
        # Cleanup temporary files (keep the exe)
        try:
            shutil.rmtree(os.path.join(build_dir, 'build'), ignore_errors=True)
            os.unlink(spec_path)
        except Exception as e:
            current_app.logger.error(f"Cleanup error: {str(e)}")