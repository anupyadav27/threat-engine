import os
import subprocess
from pathlib import Path
from saml2.sigver import CryptoBackendXmlSec1

BASE_DIR = Path(__file__).resolve().parent.parent
CONF_DIR = os.path.join(BASE_DIR, '.config')
XMLSEC_PATH = "../xmlsec/bin/xmlsec.exe"
okta_cert = os.path.join(CONF_DIR, 'okta.cert')
sp_key = os.path.join(CONF_DIR, 'sp_key.pem')
sp_cert = os.path.join(CONF_DIR, 'sp_cert.pem')


def debug_xmlsec():
    print("--- Phase 1: File Check ---")
    for name, path in [("Okta Cert", okta_cert), ("SP Key", sp_key), ("SP Cert", sp_cert)]:
        exists = os.path.exists(path)
        print(f"{name}: {'FOUND' if exists else 'MISSING'} at {path}")
        if exists:
            with open(path, 'rb') as f:
                header = f.read(20)
                print(f"   Header bytes: {header}")

    print("\n--- Phase 2: Binary Execution ---")
    try:
        ver = subprocess.run([XMLSEC_PATH, "--version"], capture_output=True, text=True)
        print(f"Binary Version: {ver.stdout.strip()}")
    except Exception as e:
        print(f"CRITICAL: Binary failed to run: {e}")
        return

    print("\n--- Phase 3: Manual Signature Verification Test ---")
    cmd = [
        XMLSEC_PATH,
        "--verify",
        "--pubkey-cert-pem", okta_cert,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    print("STDOUT:", result.stdout)
    print("STDERR:", result.stderr)

    if "invalid format" in result.stderr:
        print("\nDIAGNOSIS: The MSCrypto backend cannot read your PEM file.")
        print("FIX: We must force OpenSSL or re-encode the certificate.")


if __name__ == "__main__":
    debug_xmlsec()