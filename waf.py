import requests
import sys
from wafw00f.main import WAFW00F

def enhanced_waf_detection(domain):
    target_http = f"http://{domain}"
    target_https = f"https://{domain}"

    print(f"Attempting HTTP connection to: {target_http}")
    print(f"Attempting HTTPS connection to: {target_https}")

    try:
        # HTTP request for HTTP
        response_http = requests.get(target_http, timeout=10)
        response_http.raise_for_status()

        # Initialize wafw00f for HTTP
        w_http = WAFW00F(target_http)
        waf_detected_http = w_http.identwaf()

        if waf_detected_http:
            print(f"Web Application Firewall (WAF) detected for HTTP: {waf_detected_http}")
        else:
            print("No Web Application Firewall (WAF) detected with wafw00f for HTTP.")

        # Check for additional WAFs based on headers
        check_additional_waf(response_http.headers)

    except requests.exceptions.RequestException as e:
        print(f"Error during HTTP request: {e}")

    try:
        # HTTP request for HTTPS
        response_https = requests.get(target_https, timeout=10, verify=False)
        response_https.raise_for_status()

        # Initialize wafw00f for HTTPS
        w_https = WAFW00F(target_https)
        waf_detected_https = w_https.identwaf()

        if waf_detected_https:
            print(f"Web Application Firewall (WAF) detected for HTTPS: {waf_detected_https}")
        else:
            print("No Web Application Firewall (WAF) detected with wafw00f for HTTPS.")

        # Check for additional WAFs based on headers
        check_additional_waf(response_https.headers)

    except requests.exceptions.RequestException as e:
        print(f"Error during HTTPS request: {e}")

def check_additional_waf(headers):
    # List of additional headers to check for WAFs
    additional_headers = [
        'Server',
        'X-Powered-By',
        'X-CF-Powered-By',
        'X-CDN',
        'X-Frame-Options',
        'X-XSS-Protection',
        'X-Content-Type-Options',
        'X-Application-Context',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Runtime',
        'X-Wix-Request-Id',
        'X-Pingback',
        'X-Drupal-Cache',
        'X-Sucuri-ID'
    ]

    additional_waf_detected = False
    for header in additional_headers:
        if header in headers:
            if additional_waf_detected:
                print(f"Additional WAF detected: {headers[header]}")
            else:
                print(f"Additional WAF detected for HTTP/HTTPS: {headers[header]}")
            additional_waf_detected = True

    if not additional_waf_detected:
        print("No additional WAF detected for HTTP/HTTPS.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python waf_detection.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    enhanced_waf_detection(domain)
