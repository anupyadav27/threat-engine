import os
import sys
import logging
import base64
from urllib.parse import parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer
import webbrowser

# ==========================================
# 1. SETUP DJANGO ENVIRONMENT

# ==========================================
# Replace 'config.settings' with your actual settings module path if different
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

try:
    import django

    django.setup()
    print("[SUCCESS] Django environment loaded.")
except Exception as e:
    print(f"[ERROR] Failed to load Django environment: {e}")
    sys.exit(1)

from django.conf import settings
from djangosaml2.conf import get_config
from saml2.client import Saml2Client
import saml2

# Set up logging to see exactly what pysaml2 is doing internally
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger('saml2')
logger.setLevel(logging.DEBUG)

# Shared state to capture the SAML POST from Okta
captured_data = {}


# ==========================================
# 2. TEMPORARY HTTP SERVER TO CATCH ACS POST
# ==========================================
class ACSCaptureHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default HTTP server logs to keep terminal clean

    def do_POST(self):
        if self.path == '/api/auth/saml/acs/':
            print("\n[INFO] Caught POST request from Okta on the ACS endpoint!")
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            parsed_data = parse_qs(post_data)

            if 'SAMLResponse' in parsed_data:
                captured_data['SAMLResponse'] = parsed_data['SAMLResponse'][0]
                print("[SUCCESS] Extracted SAMLResponse payload.")
            else:
                print("[ERROR] No SAMLResponse found in the POST payload!")

            # Send a response to the browser
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """
            <html><body>
                <h2>SAML Response Captured Successfully!</h2>
                <p>You can close this tab and return to your terminal to see the decoded output.</p>
            </body></html>
            """
            self.wfile.write(html.encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()


def run_temp_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, ACSCaptureHandler)
    print("\n[STEP 3] Listening on http://localhost:8000/api/auth/saml/acs/ for Okta's callback...")
    httpd.handle_request()  # Handles exactly ONE request and then shuts down


# ==========================================
# 3. MAIN DEBUG WORKFLOW
# ==========================================
def main():
    print("\n" + "=" * 50)
    print(" SAML AUTHENTICATION DEBUGGER ".center(50))
    print("=" * 50)

    input("\nPress ENTER to load SAML Configuration and connect to Okta metadata...")

    # Load configuration
    try:
        conf = get_config()
        client = Saml2Client(conf)
        print("\n[SUCCESS] Loaded SAML Configuration and fetched remote metadata.")
    except Exception as e:
        print(f"\n[ERROR] Failed to initialize Saml2Client. Check your OKTA_METADATA url and certificates.\nError: {e}")
        return

    input("\nPress ENTER to generate the AuthNRequest (Login Request)...")

    # Generate the login request
    try:
        reqid, info = client.prepare_for_authenticate()
        redirect_url = None
        for key, value in info['headers']:
            if key == 'Location':
                redirect_url = value
                break

        if not redirect_url:
            print("[ERROR] Failed to extract redirect URL from AuthNRequest.")
            return

        print(f"\n[INFO] Generated Request ID: {reqid}")
        print(f"[INFO] Redirect URL generated successfully.")
    except Exception as e:
        print(f"\n[ERROR] Failed to prepare authentication request.\nError: {e}")
        return

    print("\n" + "=" * 50)
    print("ACTION REQUIRED:")
    print("I am about to open your default web browser.")
    print("Please log into Okta. Once you authenticate, Okta will redirect")
    print("you back to localhost, and this script will catch the response.")
    print("=" * 50)
    input("\nPress ENTER to open browser and start listening...")

    # Open browser and start listening
    webbrowser.open(redirect_url)
    run_temp_server()

    # Process the captured response
    if 'SAMLResponse' not in captured_data:
        print("\n[ERROR] Did not capture a SAMLResponse. Exiting.")
        return

    saml_response_raw = captured_data['SAMLResponse']

    input("\nPress ENTER to decode and validate the SAML Response...")

    try:
        # Outstanding requests dictionary to validate InResponseTo
        outstanding = {reqid: '/api/auth/saml/acs/'}

        # Parse and validate the response against your sp_key/sp_cert and Okta's metadata
        authn_response = client.parse_authn_request_response(
            saml_response_raw,
            saml2.entity.BINDING_HTTP_POST,
            outstanding=outstanding
        )

        if not authn_response:
            print("\n[ERROR] pysaml2 could not parse the response. It might be invalid or unsigned.")
            return

        print("\n" + "=" * 50)
        print("[SUCCESS] SAML ASSERTION VALIDATED SUCCESSFULLY!")
        print("=" * 50)

        # Extract user information
        session_info = authn_response.session_info()
        print("\n--- USER IDENTITY ---")
        print(f"NameID (Subject): {session_info.get('name_id').text}")

        print("\n--- USER ATTRIBUTES ---")
        attributes = session_info.get('ava', {})
        for attr, values in attributes.items():
            print(f"- {attr}: {values}")

    except Exception as e:
        print(f"\n[ERROR] Failed to validate SAML Assertion!")
        print(f"Exception details: {e}")
        print("\nRaw Base64 SAML Response (for manual inspection):")
        print(saml_response_raw)
        return

    input("\nPress ENTER to simulate Django User Authentication using djangosaml2 backend...")

    try:
        from django.contrib.auth import authenticate
        from django.http import HttpRequest

        # Create a mock request
        request = HttpRequest()
        request.session = {}

        # Attempt to authenticate/create user using djangosaml2 backend
        user = authenticate(request=request, session_info=session_info)

        if user:
            print(f"\n[SUCCESS] Django successfully authenticated the user!")
            print(f"User DB ID: {user.id}")
            print(f"Username/Email: {user.email}")
            print(f"Is Active: {user.is_active}")
            print(f"New User Created? (Check DB, if this was your first login, they were auto-created)")
        else:
            print("\n[ERROR] Django authenticate() returned None.")
            print(
                "This usually means SAML_ATTRIBUTE_MAPPING failed to find the necessary fields (like email) to create the user.")
            print(f"Review the attributes Okta sent: {attributes}")

    except Exception as e:
        print(f"\n[ERROR] Django authentication step failed: {e}")

    print("\n=== DEBUGGING COMPLETE ===")


if __name__ == '__main__':
    main()