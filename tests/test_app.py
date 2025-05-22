import unittest
from app import app

class TestApp(unittest.TestCase):
    def setUp(self):
        # Create a test client
        self.app = app.test_client()
        # Propagate the exceptions to the test client
        self.app.testing = True

    def test_app_creation(self):
        self.assertIsNotNone(app, "Flask app should be created")

    def test_reports_route(self):
        response = self.app.get('/reports')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Reports Page", response.data)

    def test_devices_overview_route(self):
        response = self.app.get('/devices_overview')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Device Routes Page", response.data)

if __name__ == '__main__':
    unittest.main()
