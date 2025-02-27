import asyncio
import json
from datetime import datetime
import socketio
from flask import current_app
from models import Device, DeviceMetrics, Alert, AlertRule
from database import db

sio = socketio.AsyncServer(async_mode='asgi')

@sio.event
async def connect(sid, environ):
    print(f"Client connected: {sid}")

@sio.event
async def disconnect(sid):
    print(f"Client disconnected: {sid}")

@sio.event
async def device_metrics(sid, data):
    device_id = data.get('device_id')
    metrics = data.get('metrics')
    
    if not device_id or not metrics:
        return {'error': 'Invalid data'}
    
    try:
        # Update device metrics
        device_metric = DeviceMetrics(
            device_id=device_id,
            cpu_usage=metrics.get('cpu_usage'),
            memory_used=metrics.get('memory_used'),
            disk_used=metrics.get('disk_used'),
            network_bytes_sent=metrics.get('network_bytes_sent'),
            network_bytes_received=metrics.get('network_bytes_received')
        )
        db.session.add(device_metric)
        
        # Check alert rules
        await check_alert_rules(device_id, metrics)
        
        db.session.commit()
        
        # Broadcast updated metrics to all connected clients
        await sio.emit('metrics_update', {
            'device_id': device_id,
            'metrics': metrics,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        return {'status': 'success'}
        
    except Exception as e:
        db.session.rollback()
        print(f"Error processing metrics: {e}")
        return {'error': str(e)}

async def check_alert_rules(device_id, metrics):
    rules = AlertRule.query.filter_by(enabled=True).all()
    
    for rule in rules:
        value = metrics.get(rule.metric_type)
        if value is None:
            continue
            
        # Check if threshold is exceeded
        condition_met = False
        if rule.condition == '>':
            condition_met = value > rule.threshold
        elif rule.condition == '<':
            condition_met = value < rule.threshold
        elif rule.condition == '>=':
            condition_met = value >= rule.threshold
        elif rule.condition == '<=':
            condition_met = value <= rule.threshold
        
        if condition_met:
            alert = Alert(
                rule_id=rule.id,
                device_id=device_id,
                value=value,
                message=f"{rule.metric_type} {rule.condition} {rule.threshold}"
            )
            db.session.add(alert)
            
            # Emit alert to connected clients
            await sio.emit('new_alert', {
                'device_id': device_id,
                'alert': {
                    'type': rule.metric_type,
                    'severity': rule.severity,
                    'message': alert.message,
                    'timestamp': datetime.utcnow().isoformat()
                }
            })
