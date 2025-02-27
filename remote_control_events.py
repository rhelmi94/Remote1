from flask_socketio import emit, join_room, leave_room
from app import socketio
from models import RemoteSession, Device
from flask_login import current_user
import logging
import psutil
import base64
import cv2
import numpy as np
import io

logger = logging.getLogger(__name__)

@socketio.on('connect', namespace='/remote')
def handle_remote_connect():
    """Handle remote control connection"""
    if not current_user.is_authenticated:
        return False
    
    connection_id = request.args.get('connection_id')
    if not connection_id:
        return False
        
    session = RemoteSession.query.filter_by(connection_id=connection_id).first()
    if not session or session.user_id != current_user.id:
        return False
        
    join_room(connection_id)
    emit('connection_status', {'status': 'connected'})
    return True

@socketio.on('disconnect', namespace='/remote')
def handle_remote_disconnect():
    """Handle remote control disconnection"""
    connection_id = request.args.get('connection_id')
    if connection_id:
        leave_room(connection_id)
        session = RemoteSession.query.filter_by(connection_id=connection_id).first()
        if session:
            session.status = 'ended'
            session.ended_at = datetime.utcnow()
            db.session.commit()

@socketio.on('screen_capture', namespace='/remote')
def handle_screen_capture(data):
    """Handle screen capture updates"""
    try:
        connection_id = data.get('connection_id')
        session = RemoteSession.query.filter_by(connection_id=connection_id).first()
        
        if not session or session.user_id != current_user.id:
            return
            
        # Get screenshot using cv2
        screen = pyautogui.screenshot()
        screen_np = np.array(screen)
        _, buffer = cv2.imencode('.jpg', screen_np)
        screen_base64 = base64.b64encode(buffer).decode('utf-8')
        
        emit('screen_data', {'screen': screen_base64}, room=connection_id)
        
        # Send system metrics
        metrics = {
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters()._asdict()
        }
        emit('metrics_update', metrics, room=connection_id)
        
    except Exception as e:
        logger.error(f"Error capturing screen: {e}")
        emit('error', {'message': 'Failed to capture screen'}, room=connection_id)

@socketio.on('send_keys', namespace='/remote')
def handle_send_keys(data):
    """Handle keyboard input"""
    try:
        connection_id = data.get('connection_id')
        keys = data.get('keys')
        session = RemoteSession.query.filter_by(connection_id=connection_id).first()
        
        if not session or session.user_id != current_user.id:
            return
            
        if keys == 'ctrl+alt+del':
            # Special key combination handling
            pyautogui.hotkey('ctrl', 'alt', 'del')
        else:
            # Normal key press
            pyautogui.press(keys)
            
    except Exception as e:
        logger.error(f"Error sending keys: {e}")
        emit('error', {'message': 'Failed to send keyboard input'}, room=connection_id)

@socketio.on('chat_message', namespace='/remote')
def handle_chat_message(data):
    """Handle chat messages"""
    connection_id = data.get('connection_id')
    message = data.get('message')
    session = RemoteSession.query.filter_by(connection_id=connection_id).first()
    
    if not session or session.user_id != current_user.id:
        return
        
    emit('chat_message', {
        'sender': current_user.username,
        'message': message,
        'timestamp': datetime.utcnow().isoformat()
    }, room=connection_id)
