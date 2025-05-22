import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

logger.info("Initializing Flask application...")

class Base(DeclarativeBase):
    pass

# Initialize Flask and extensions
db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Configure the database
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

logger.debug(f"Configuring database with URL: {database_url.split('@')[-1] if database_url and '@' in database_url else database_url or 'None'}")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize database
logger.info("Initializing database...")
db.init_app(app)

# Initialize login manager
logger.info("Setting up login manager...")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Import all models first
logger.info("Importing models...")
try:
    from models import (
        User, SystemMetric, Device, DeviceGroup,
        DeviceSession, RemoteScript, ScriptExecution,
        RemoteSession, AgentInstallCode, BulkDeployment,
        DeploymentResult
    )
    logger.debug("Models imported successfully")
except Exception as e:
    logger.error("Error importing models:", exc_info=True)
    raise

# Create database tables
logger.info("Updating database tables...")
try:
    with app.app_context():
        db.create_all()
        logger.debug("Database tables updated successfully")
except Exception as e:
    logger.error("Error updating database tables:", exc_info=True)
    raise

# Import blueprints
logger.info("Importing blueprints...")
try:
    from auth import auth_bp
    logger.debug("Imported auth_bp")
    from system_monitor import monitor_bp
    logger.debug("Imported monitor_bp")
    from file_handler import files_bp
    logger.debug("Imported files_bp")
    from process_manager import process_bp
    logger.debug("Imported process_bp")
    from remote_control import remote_bp
    logger.debug("Imported remote_bp")
    from admin import admin_bp
    logger.debug("Imported admin_bp")
    from bulk_deployment import bulk_bp
    logger.debug("Imported bulk_bp")
    from routes.reporting import reports_bp
    logger.debug("Imported reports_bp")
    from routes.device_routes import device_routes
    logger.debug("Imported device_routes")
except Exception as e:
    logger.error("Error importing blueprints:", exc_info=True)
    raise

# Register blueprints
logger.info("Registering blueprints...")
try:
    app.register_blueprint(auth_bp)
    app.register_blueprint(monitor_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(process_bp)
    app.register_blueprint(remote_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(bulk_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(device_routes)
    logger.debug("All blueprints registered successfully")
except Exception as e:
    logger.error("Error registering blueprints:", exc_info=True)
    raise

logger.info("Flask application initialization complete")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)