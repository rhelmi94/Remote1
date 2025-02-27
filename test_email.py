import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content

def send_test_email():
    try:
        # Get credentials from environment
        api_key = os.environ.get('drmogczgghrpqnuv')
        from_email = os.environ.get('mcemng2@gmail.com')
        
        # Create the email
        message = Mail(
            from_email=Email(from_email),
            to_emails=To(from_email),  # Sending to the same email for testing
            subject='Test Email from Remote Access Tool',
            html_content='<strong>This is a test email to verify SendGrid integration.</strong>'
        )
        
        # Send the email
        sg = SendGridAPIClient(api_key=api_key)
        response = sg.send(message)
        print(f"Email sent! Status code: {response.status_code}")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

if __name__ == "__main__":
    send_test_email()
