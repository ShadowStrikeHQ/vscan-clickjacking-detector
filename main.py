import argparse
import requests
import logging
from bs4 import BeautifulSoup
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Detects clickjacking vulnerabilities.")
    parser.add_argument("url", help="The URL to scan for clickjacking vulnerability.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser

def check_clickjacking(url):
    """
    Checks if a website is vulnerable to clickjacking by analyzing HTTP headers
    and the presence of frame busting techniques in the HTML.

    Args:
        url (str): The URL to check.

    Returns:
        tuple: A tuple containing a boolean indicating vulnerability (True if vulnerable, False otherwise)
               and a message string explaining the result.
    """
    try:
        # Validate URL format (basic check)
        if not url.startswith(('http://', 'https://')):
            return True, "Invalid URL format. Must start with http:// or https://. Assuming vulnerable for safety."

        # Send an HTTP request to the URL
        try:
            response = requests.get(url, timeout=10) # Added timeout
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            return True, f"Request failed: {e}. Assuming vulnerable for safety."

        # Check for X-Frame-Options header
        x_frame_options = response.headers.get("X-Frame-Options")
        if x_frame_options:
            logging.info(f"X-Frame-Options header found: {x_frame_options}")
            return False, f"X-Frame-Options header found: {x_frame_options}. Site is likely protected."
        else:
            logging.warning("X-Frame-Options header not found.")

        # Check for Content-Security-Policy header
        content_security_policy = response.headers.get("Content-Security-Policy")
        if content_security_policy:
            logging.info(f"Content-Security-Policy header found: {content_security_policy}")
            if "frame-ancestors" in content_security_policy or "frame-src" in content_security_policy:
                return False, f"Content-Security-Policy header found: {content_security_policy}. Site is likely protected."
            else:
                logging.warning("Content-Security-Policy found, but frame-ancestors or frame-src not present.")

        else:
            logging.warning("Content-Security-Policy header not found.")

        # Check for frame busting JavaScript in the HTML
        soup = BeautifulSoup(response.text, "html.parser")
        frame_busting_script = soup.find("script", text=lambda text: text and "TOP_LEVEL" in text) #Example of javascript frame busting technique
        if frame_busting_script:
             logging.info("Frame busting JavaScript found.")
             return False, "Frame busting JavaScript found. Site is likely protected."

        # If no X-Frame-Options, CSP, or frame busting script is found, the site is potentially vulnerable
        return True, "No X-Frame-Options or Content-Security-Policy header or frame busting script found. Site may be vulnerable to clickjacking."

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        return True, f"An unexpected error occurred: {e}. Assuming vulnerable for safety."


def main():
    """
    The main function of the script.  Parses arguments, calls the clickjacking check, and prints the results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    url = args.url

    # Sanitize URL to prevent command injection
    # While not strictly necessary for clickjacking detection, it's good practice
    # Consider using a more robust sanitization library if needed
    url = url.replace(";", "")  # Remove semicolons
    url = url.replace("&", "")  # Remove ampersands

    # Added input validation and normalization
    if not isinstance(url, str):
        print("Error: URL must be a string.")
        sys.exit(1)

    if not url:
        print("Error: URL cannot be empty.")
        sys.exit(1)

    # Check URL for safety
    if any(char in url for char in ['<', '>', '"', "'", '%', '#', '\\']):  # Basic check
        print("Warning: potentially unsafe characters in URL.  Proceed with caution.")
        
    is_vulnerable, message = check_clickjacking(url)

    if is_vulnerable:
        print(f"[VULNERABLE] {url}: {message}")
        logging.warning(f"{url}: Vulnerable to clickjacking. {message}")
    else:
        print(f"[NOT VULNERABLE] {url}: {message}")
        logging.info(f"{url}: Not vulnerable to clickjacking. {message}")


if __name__ == "__main__":
    # Example Usage:
    # python vscan_clickjacking_detector.py https://example.com
    # python vscan_clickjacking_detector.py http://example.com -v

    main()