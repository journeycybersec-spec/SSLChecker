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
# Fixed: Removed 'DH' and 'RSA' which are too broad and flag modern ciphers incorrectly
WEAK_CIPHERS = ['RC4', 'DES-CBC3', '3DES', 'NULL', 'EXPORT', 'IDEA', 'SEED', 'MD5', 'anon']
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
        
        # Calculate days until expiration
        days_remaining = (not_after - datetime.now(timezone.utc)).days
        if days_remaining < 30:
            return f"⚠️  Valid (expires in {days_remaining} days)"
        
        return f"✅ Valid (expires in {days_remaining} days)"
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
    return f"✅ Protocols OK ({protocol})"

# Check for weak ciphers
def check_ciphers(cipher):
    cipher_name = cipher[0]
    weak_ciphers = [weak for weak in WEAK_CIPHERS if weak in cipher_name]
    if weak_ciphers:
        return f"❌ Weak Ciphers Detected: {', '.join(weak_ciphers)}"
    return "✅ Ciphers OK"

# Check for Forward Secrecy (PFS)
def check_forward_secrecy(cipher, protocol):
    cipher_name = cipher[0]
    # TLS 1.3 always uses forward secrecy
    if protocol == 'TLSv1.3':
        return "✅ Forward Secrecy Enabled (TLS 1.3)"
    # For older protocols, check for ECDHE or DHE
    if 'ECDHE' in cipher_name or 'DHE' in cipher_name:
        return "✅ Forward Secrecy Enabled"
    return "❌ No Forward Secrecy"

# Check for certificate domain mismatch (FIXED)
def check_domain(cert, hostname):
    try:
        # Extract the common name from the subject
        subject_dict = dict(x[0] for x in cert['subject'])
        common_name = subject_dict.get('commonName', '')
        
        # Also check Subject Alternative Names (SANs)
        san_list = []
        if 'subjectAltName' in cert:
            san_list = [name for name_type, name in cert['subjectAltName'] if name_type == 'DNS']
        
        # Check if hostname matches CN or any SAN
        if common_name == hostname or hostname in san_list:
            return "✅ Domain OK"
        
        # Check for wildcard matches
        for san in san_list:
            if san.startswith('*.'):
                wildcard_domain = san[2:]  # Remove '*.'
                if hostname.endswith(wildcard_domain):
                    return f"✅ Domain OK (wildcard match: {san})"
        
        if san_list:
            return f"❌ Domain Mismatch: Certificate issued for {common_name} (SANs: {', '.join(san_list[:3])}), not {hostname}"
        else:
            return f"❌ Domain Mismatch: Certificate issued for {common_name}, not {hostname}"
            
    except Exception as e:
        logging.error(f"Error checking domain: {str(e)}")
        return "❌ Error checking domain"

# Check for weak signature algorithm (SHA1)
def check_signature(hostname):
    try:
        # Need to get the raw certificate in binary form
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the certificate in DER format
                cert_der = ssock.getpeercert(binary_form=True)
                
        # Parse the certificate
        cert_obj = load_pem_x509_certificate(
            ssl.DER_cert_to_PEM_cert(cert_der).encode(), 
            default_backend()
        )
        
        signature_algorithm = cert_obj.signature_algorithm_oid._name

        if any(weak in signature_algorithm.lower() for weak in WEAK_SIGNATURES):
            return f"❌ Weak Signature Algorithm: {signature_algorithm}"
        return f"✅ Signature OK ({signature_algorithm})"
    except Exception as e:
        logging.error(f"Error parsing certificate signature: {str(e)}")
        return "❌ Error retrieving signature"

# Check for certificate chain (FIXED - actually validates the chain)
def check_certificate_chain(hostname):
    """Actually validate the certificate chain by attempting a verified connection"""
    try:
        context = ssl.create_default_context()
        # This will raise an exception if chain validation fails
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # If we get here, the chain is valid
                cert = ssock.getpeercert()
                issuer_dict = dict(x[0] for x in cert['issuer'])
                issuer_cn = issuer_dict.get('commonName', 'Unknown')
                
                # Count the chain depth if available
                return f"✅ Valid Certificate Chain (Issuer: {issuer_cn})"
    except ssl.SSLCertVerificationError as e:
        logging.error(f"Certificate chain validation failed: {str(e)}")
        return f"❌ Invalid Certificate Chain: {e.verify_message}"
    except socket.timeout:
        logging.error(f"Timeout validating certificate chain for {hostname}")
        return "❌ Certificate Chain Validation Timeout"
    except Exception as e:
        logging.error(f"Error validating certificate chain: {str(e)}")
        return "❌ Certificate Chain Validation Error"

# Check for HSTS (HTTP Strict Transport Security)
def check_hsts(url):
    try:
        response = requests.get(f'https://{url}', timeout=5)
        if 'Strict-Transport-Security' in response.headers:
            hsts_value = response.headers['Strict-Transport-Security']
            return f"✅ HSTS Enabled ({hsts_value})"
        return "❌ HSTS Not Enabled"
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking HSTS for {url}: {str(e)}")
        return "❌ HSTS Check Failed"

# Function to print the SSL/TLS analysis in a human-readable format
def print_ssl_report(domain, cert_status, self_signed_status, protocol_status, cipher_status, 
                    forward_secrecy_status, domain_status, signature_status, certificate_chain_status, 
                    hsts_status, cipher_suite):
    print(f"\nPerforming SSL/TLS analysis for {domain}...\n")
    print("=" * 70)
    print(f"Domain Information for: {domain}")
    print("-" * 70)
    print(f"Certificate: {cert_status}")
    print(f"Self-Signed: {self_signed_status}")
    print(f"Protocol Status: {protocol_status}")
    print(f"Cipher Suite: {cipher_suite}")
    print(f"Cipher Strength: {cipher_status}")
    print(f"Forward Secrecy: {forward_secrecy_status}")
    print(f"Domain Status: {domain_status}")
    print(f"Signature Algorithm: {signature_status}")
    print(f"Certificate Chain: {certificate_chain_status}")
    print(f"HSTS: {hsts_status}")
    print("=" * 70)

# Main function to run the checker
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="SSL/TLS Checker - Validate SSL/TLS configuration")
    parser.add_argument("hostname", help="The hostname or domain to check (without https://)")
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
    forward_secrecy_status = check_forward_secrecy(cipher, protocol)  # Fixed: Pass protocol
    domain_status = check_domain(cert, args.hostname)
    signature_status = check_signature(args.hostname)  # Fixed: Pass hostname not cert
    certificate_chain_status = check_certificate_chain(args.hostname)  # Fixed: Pass hostname not cert
    hsts_status = check_hsts(args.hostname)

    # Get the cipher suite for display
    cipher_suite = cipher[0] if cipher else "N/A"

    # Output results in formatted style
    print_ssl_report(args.hostname, cert_status, self_signed_status, protocol_status, cipher_status, 
                    forward_secrecy_status, domain_status, signature_status, certificate_chain_status, 
                    hsts_status, cipher_suite)

if __name__ == "__main__":
    main()
