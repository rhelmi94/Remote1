import logging
import traceback
from datetime import datetime

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    try:
        logger.info("Beginning Flask server initialization...")

        # Import the Flask app
        logger.debug("Importing Flask application...")
        from app import app

        logger.info("Starting Flask server...")
        app.run(
            host="0.0.0.0",
            port=5000,
            debug=True,
            use_reloader=False
        )
    except ImportError as ie:
        logger.error("Import error during server startup:")
        logger.error(traceback.format_exc())
        raise
    except Exception as e:
        logger.error("Failed to start server:")
        logger.error(traceback.format_exc())
        raise