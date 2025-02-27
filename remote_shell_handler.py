import os
import pty
import select
import subprocess
import threading
import time
from datetime import datetime, timedelta
from flask import current_app, request
from flask_socketio import emit, disconnect
from flask_login import current_user
from app import socketio, db
from models import Device, ShellSession

class RateLimiter:
    def __init__(self, max_commands=10, window_seconds=60):
        self.max_commands = max_commands
        self.window_seconds = window_seconds
        self.commands = []

    def can_execute(self):
        now = datetime.utcnow()
        # Remove old commands outside the window
        self.commands = [t for t in self.commands 
                        if t > now - timedelta(seconds=self.window_seconds)]
        return len(self.commands) < self.max_commands

    def record_command(self):
        self.commands.append(datetime.utcnow())

class RemoteShellSession:
    def __init__(self, device_id, user_id):
        self.device_id = device_id
        self.user_id = user_id
        self.master_fd = None
        self.slave_fd = None
        self.process = None
        self.running = False
        self.read_thread = None
        self.last_activity = datetime.utcnow()
        self.rate_limiter = RateLimiter()
        self.command_history = []
        self.session_start = datetime.utcnow()

    def start(self):
        try:
            # Create pseudo-terminal
            self.master_fd, self.slave_fd = pty.openpty()

            # Set terminal size
            os.system(f'stty rows 24 cols 80 < /dev/tty{os.ttyname(self.slave_fd)}')

            # Start shell process with restricted capabilities
            self.process = subprocess.Popen(
                ['/bin/bash'],
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                preexec_fn=os.setsid,
                start_new_session=True,
                env={
                    'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                    'TERM': 'xterm-256color',
                    'SHELL': '/bin/bash'
                }
            )

            self.running = True

            # Record session start
            session = ShellSession(
                device_id=self.device_id,
                user_id=self.user_id,
                start_time=self.session_start
            )
            db.session.add(session)
            db.session.commit()

            # Start output reading thread
            self.read_thread = threading.Thread(target=self._read_output)
            self.read_thread.daemon = True
            self.read_thread.start()

            # Start timeout monitoring thread
            self.timeout_thread = threading.Thread(target=self._monitor_timeout)
            self.timeout_thread.daemon = True
            self.timeout_thread.start()

            return True
        except Exception as e:
            current_app.logger.error(f"Failed to start shell session: {e}")
            return False

    def stop(self):
        self.running = False
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), 9)
            except OSError:
                pass

        if self.master_fd:
            os.close(self.master_fd)
        if self.slave_fd:
            os.close(self.slave_fd)

        # Record session end
        session = ShellSession.query.filter_by(
            device_id=self.device_id,
            user_id=self.user_id,
            end_time=None
        ).first()
        if session:
            session.end_time = datetime.utcnow()
            session.command_count = len(self.command_history)
            db.session.commit()

    def write(self, data):
        if not self.rate_limiter.can_execute():
            emit('error', {'error': 'Command rate limit exceeded'})
            return False

        if self.master_fd:
            try:
                self.rate_limiter.record_command()
                self.last_activity = datetime.utcnow()
                self.command_history.append({
                    'command': data.strip(),
                    'timestamp': datetime.utcnow()
                })
                os.write(self.master_fd, data.encode())
                return True
            except OSError as e:
                current_app.logger.error(f"Failed to write to shell: {e}")
                return False
        return False

    def _read_output(self):
        while self.running:
            try:
                r, _, _ = select.select([self.master_fd], [], [], 0.1)
                if self.master_fd in r:
                    output = os.read(self.master_fd, 1024).decode(errors='replace')
                    emit('output', {'output': output})
                    self.last_activity = datetime.utcnow()
            except (OSError, select.error) as e:
                current_app.logger.error(f"Error reading from shell: {e}")
                break
        self.stop()

    def _monitor_timeout(self):
        timeout_minutes = 30  # Session timeout after 30 minutes of inactivity
        while self.running:
            if datetime.utcnow() - self.last_activity > timedelta(minutes=timeout_minutes):
                current_app.logger.info("Shell session timed out due to inactivity")
                emit('timeout', {'message': 'Session timed out due to inactivity'})
                self.stop()
                break
            time.sleep(60)  # Check every minute

# Dictionary to store active shell sessions
shell_sessions = {}

@socketio.on('connect', namespace='/shell')
def shell_connect():
    """Handle shell connection"""
    device_id = request.args.get('device_id')
    if not device_id:
        emit('error', {'error': 'No device ID provided'})
        disconnect()
        return False

    if not current_user.is_authenticated:
        emit('error', {'error': 'Authentication required'})
        disconnect()
        return False

    # Check if device exists and user has access
    device = Device.query.get(device_id)
    if not device or not device.can_access(current_user):
        emit('error', {'error': 'Unauthorized access to device'})
        disconnect()
        return False

    session = RemoteShellSession(device_id, current_user.id)
    if not session.start():
        emit('error', {'error': 'Failed to start shell session'})
        disconnect()
        return False

    shell_sessions[request.sid] = session
    emit('connected', {
        'message': 'Shell session started',
        'device_name': device.name,
        'session_start': session.session_start.isoformat()
    })
    return True

@socketio.on('disconnect', namespace='/shell')
def shell_disconnect():
    """Handle shell disconnection"""
    session = shell_sessions.pop(request.sid, None)
    if session:
        session.stop()

@socketio.on('command', namespace='/shell')
def handle_command(data):
    """Handle shell command"""
    session = shell_sessions.get(request.sid)
    if not session:
        emit('error', {'error': 'No active session'})
        return

    command = data.get('command', '').strip()
    if not command:
        return

    # Block potentially dangerous commands
    blocked_commands = ['rm -rf', 'mkfs', 'dd', 'format']
    if any(cmd in command.lower() for cmd in blocked_commands):
        emit('error', {'error': 'Command not allowed for security reasons'})
        return

    if not session.write(command + '\n'):
        emit('error', {'error': 'Failed to send command'})

@socketio.on('resize', namespace='/shell')
def handle_resize(data):
    """Handle terminal resize event"""
    session = shell_sessions.get(request.sid)
    if not session or not session.slave_fd:
        return

    rows = data.get('rows', 24)
    cols = data.get('cols', 80)

    try:
        os.system(f'stty rows {rows} cols {cols} < /dev/tty{os.ttyname(session.slave_fd)}')
    except Exception as e:
        current_app.logger.error(f"Failed to resize terminal: {e}")