from flask import Blueprint

device_routes = Blueprint('device_routes', __name__)

@device_routes.route('/devices_overview')
def overview():
    return "Device Routes Page"
