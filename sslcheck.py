import ssl
import socket
import requests
import logging
import argparse
from datetime import datetime, timezone
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

# Set up logging
logging.basicConfig(filename='ssl_checker.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define deprecated protocols, weak ciphers, and insecure signature algorithms
DEPRECATED_PROTOCOLS = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'DH', 'RSA', 'IDEA', 'SEED', 'CAMELLIA', 'MD5']
WEAK_SIGNATURES = ['sha1']

# Function to get SSL certificate and cipher suite info
def ssl_info(hostname):
    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                return cert, cipher, ssock.version()
    except Exception as e:
        logging.error(f"Error connecting to {hostname}: {str(e)}")
        return None, None, None

# Check certificate validity
def check_certificate(cert):
    try:
        # Check certificate expiration date and make it timezone-aware
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
        not_after = not_after.replace(tzinfo=timezone.utc)  # Make it UTC aware
        
        # Compare with the current UTC time
        if not_after < datetime.now(timezone.utc):
            return "❌ Expired"
        return "✅ Valid"
    except KeyError:
        logging.error("Certificate does not have expiration date.")
        return "❌ Invalid Certificate"

# Check for self-signed certificates
def check_self_signed(cert):
    if cert['issuer'] == cert['subject']:
        return "❌ Self-Signed Certificate"
    return "✅ Not Self-Signed"

# Check for deprecated protocols
def check_protocols(protocol):
    if protocol in DEPRECATED_PROTOCOLS:
        return f"❌ Deprecated Protocol Detected: {protocol}"
    return "✅ Protocols OK"

# Check for weak ciphers
def check_ciphers(cipher):
    weak_ciphers = [weak for weak in WEAK_CIPHERS if weak in cipher[0]]
    if weak_ciphers:
        return f"❌ Weak Ciphers Detected: {', '.join(weak_ciphers)}"
    return "✅ Ciphers OK"

# Check for Forward Secrecy (PFS)
def check_forward_secrecy(cipher):
    if 'ECDHE' in cipher[0] or 'DHE' in cipher[0]:
        return "✅ Forward Secrecy Enabled"
    return "❌ No Forward Secrecy"

# Check for certificate domain mismatch
def check_domain(cert, hostname):
    if cert['subject'] and cert['subject'] != hostname:
        return f"❌ Domain Mismatch: Certificate issued for {cert['subject']}, not {hostname}"
    return "✅ Domain OK"

# Check for weak signature algorithm (SHA1)
def check_signature(cert):
    try:
        cert_pem = ssl.DER_cert_to_PEM_cert(cert['cert'])
        cert_obj = load_pem_x509_certificate(cert_pem.encode(), default_backend())
        
        signature_algorithm = cert_obj.signature_algorithm_oid._name  # This extracts the signature algorithm

        if any(weak in signature_algorithm.lower() for weak in WEAK_SIGNATURES):
            return f"❌ Weak Signature Algorithm: {signature_algorithm}"
        return "✅ Signature OK"
    except Exception as e:
        logging.error(f"Error parsing certificate signature: {str(e)}")
        return "❌ Error retrieving signature"

# Check for certificate chain
def check_certificate_chain(cert):
    try:
        cert_pem = ssl.DER_cert_to_PEM_cert(cert['cert'])
        cert_obj = load_pem_x509_certificate(cert_pem.encode(), default_backend())
        return f"✅ Certificate Subject: {cert_obj.subject}"
    except Exception as e:
        logging.error(f"Error parsing certificate chain: {str(e)}")
        return "❌ Invalid Certificate Chain"

# Check for HSTS (HTTP Strict Transport Security)
def check_hsts(url):
    try:
        response = requests.get(f'https://{url}', timeout=5)
        if 'Strict-Transport-Security' in response.headers:
            return "✅ HSTS Enabled"
        return "❌ HSTS Not Enabled"
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking HSTS for {url}: {str(e)}")
        return "❌ HSTS Check Failed"

# Function to print the SSL/TLS analysis in a human-readable format
def print_ssl_report(domain, cert_status, self_signed_status, protocol_status, cipher_status, forward_secrecy_status, domain_status, signature_status, certificate_chain_status, hsts_status, cipher_suite):
    print(f"\nPerforming SSL/TLS analysis for {domain}...\n")
    print("=" * 40)
    print(f"Domain Information for: {domain}")
    print("-" * 40)
    print(f"Certificate: {cert_status}")
    print(f"Self-Signed: {self_signed_status}")
    print(f"Protocol Status: {protocol_status}")
    print(f"Cipher Suite: {cipher_suite}")
    print(f"Forward Secrecy: {forward_secrecy_status}")
    print(f"Domain Status: {domain_status}")
    print(f"Signature Algorithm: {signature_status}")
    print(f"Certificate Chain: {certificate_chain_status}")
    print(f"HSTS: {hsts_status}")
    print("=" * 40)

# Main function to run the checker
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="SSL/TLS Checker")
    parser.add_argument("hostname", help="The hostname or domain to check")
    args = parser.parse_args()

    # Retrieve SSL/TLS info for the domain
    cert, cipher, protocol = ssl_info(args.hostname)
    
    if not cert or not cipher:
        print(f"Could not retrieve SSL info for {args.hostname}. Check logs for more details.")
        return

    # Perform the checks
    cert_status = check_certificate(cert)
    self_signed_status = check_self_signed(cert)
    protocol_status = check_protocols(protocol)
    cipher_status = check_ciphers(cipher)
    forward_secrecy_status = check_forward_secrecy(cipher)
    domain_status = check_domain(cert, args.hostname)
    signature_status = check_signature(cert)
    certificate_chain_status = check_certificate_chain(cert)
    hsts_status = check_hsts(args.hostname)

    # Get the cipher suite for display
    cipher_suite = cipher[0] if cipher else "N/A"

    # Output results in formatted style
    print_ssl_report(args.hostname, cert_status, self_signed_status, protocol_status, cipher_status, forward_secrecy_status, domain_status, signature_status, certificate_chain_status, hsts_status, cipher_suite)

if __name__ == "__main__":
    main()
