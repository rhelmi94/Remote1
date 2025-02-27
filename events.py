from flask_socketio import emit
from app import socketio
import logging

logger = logging.getLogger(__name__)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    try:
        logger.info("Client connected")
        emit('connection_status', {'status': 'connected'})
    except Exception as e:
        logger.error(f"Connection error: {str(e)}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    try:
        logger.info("Client disconnected")
    except Exception as e:
        logger.error(f"Disconnection error: {str(e)}")

@socketio.on('test_event')
def handle_test_event(data):
    """Test event handler for debugging"""
    try:
        logger.info(f"Received test event: {data}")
        emit('test_response', {'status': 'success', 'message': 'Test event received'})
    except Exception as e:
        logger.error(f"Test event error: {str(e)}")