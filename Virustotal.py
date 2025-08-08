
import requests
import json
import time
import logging

# Configure Logging
logging.basicConfig(
    filename="virus_total_scan_results.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# VirusTotal API Key
API_KEY = ""

# VirusTotal API Endpoints
VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_REPORT_URL = "https://www.virustotal.com/api/v3/analyses/{}"


# Function to submit URL for scanning
def scan_url(url):
    headers = {"x-apikey": API_KEY}
    payload = {"url": url}

    try:
        response = requests.post(VIRUSTOTAL_SCAN_URL, headers=headers, data=payload)

        if response.status_code == 200:
            scan_id = response.json().get('data', {}).get('id')
            print(f"✅ URL submitted successfully: {url}")
            print(f"🔍 Scan ID: {scan_id}")
            logging.info(f"URL submitted successfully: {url} | Scan ID: {scan_id}")
            return scan_id
        else:
            print(f"❌ Failed to submit URL: {url} (Status Code: {response.status_code})")
            logging.error(f"Failed to submit URL: {url} (Status Code: {response.status_code})")
            return None
    except Exception as e:
        print(f"❌ Error occurred while submitting URL: {url} | {e}")
        logging.error(f"Error occurred while submitting URL: {url} | {e}")
        return None


# Function to retrieve and display the report
def get_report(scan_id):
    headers = {"x-apikey": API_KEY}
    report_url = VIRUSTOTAL_REPORT_URL.format(scan_id)

    try:
        # Wait for VirusTotal to process the scan
        time.sleep(15)

        response = requests.get(report_url, headers=headers)
        if response.status_code == 200:
            report_data = response.json()

            print("\n--- Threat Report ---")
            threats_found = False
            for engine, result in report_data['data']['attributes']['results'].items():
                if result['category'] != 'undetected':
                    threats_found = True
                    print(f"{engine}: {result['result']}")
                    logging.info(f"{engine}: {result['result']}")

            if not threats_found:
                print("✅ No threats detected.")
                logging.info("No threats detected.")
        else:
            print(f"❌ Failed to retrieve report. Status code: {response.status_code}")
            logging.error(f"Failed to retrieve report. Status code: {response.status_code}")
    except Exception as e:
        print(f"❌ Error while fetching the report: {e}")
        logging.error(f"Error while fetching the report: {e}")


# Main Function for User Input
if __name__ == "__main__":
    print("🔒 VirusTotal URL Scanner Automation 🔒")
    print("=====================================")

    urls_to_scan = input("Enter URLs to scan (comma-separated): ").strip().split(",")

    for url in urls_to_scan:
        url = url.strip()  # Clean spaces
        if url:
            scan_id = scan_url(url)
            if scan_id:
                get_report(scan_id)
            print("\n" + "=" * 40 + "\n")

    print("📋 Scan results saved in 'virus_total_scan_results.log'.")
