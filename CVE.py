import requests
import concurrent.futures
from colorama import Fore, Style, init
import argparse

# Initialize colorama
init(autoreset=True)

# Constants for API URLs
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CIRCL_API_BASE_URL = "https://cve.circl.lu/api/cve/"
VULNERS_API_BASE_URL = "https://vulners.com/api/v3/search/lucene/"
EPSS_API_BASE_URL = "https://api.first.org/data/v1/epss"

DEFAULT_RESULTS_DISPLAY = 5
MAX_RESULTS_DISPLAY = 10

# Function to display the tool name as ASCII art
def display_tool_name():
    tool_art = """
           ____     ______   ______  ______   ______  ______
         .'    '.  |  ____| |  ____||  ____| |  ____||  ____|
        :        : | |____  | |____ | |____  | |____ | |____
        |        | |  ____| |____  ||____  | |____  ||  ____|
        :        ; | |____   ____| | ____| |  ____| || |____
         '.__.__.' |______| |______||______| |______||______|
    """
    print(Fore.CYAN + tool_art)

# NVD Search Function
def search_nvd(cve_id, api_key=None):
    try:
        url = f"{NVD_API_BASE_URL}?cveId={cve_id}"
        headers = {}
        if api_key:
            headers['apiKey'] = api_key
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("vulnerabilities", [])
            if data:
                nvd_result = {
                    "summary": data[0].get('cve', {}).get('descriptions', [{}])[0].get('value', 'No description available'),
                    "cvss_score": data[0].get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A'),
                    "products": [cpe.get('criteria', 'Unknown product') for node in data[0].get('configurations', {}).get('nodes', []) for cpe in node.get('cpeMatch', []) if 'product' in cpe.get('criteria', '').lower()]
                }
                return {"source": "NVD", "results": nvd_result}
        return []
    except Exception as e:
        print(f"[ERROR] Failed to query NVD for {cve_id}: {e}")
        return []

# CIRCL Search Function
def search_circl(cve_id):
    try:
        url = f"{CIRCL_API_BASE_URL}{cve_id}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict):
                circl_result = {
                    "summary": data.get('summary', 'No description available'),
                    "cvss_score": data.get('cvss', 'N/A'),
                    "products": [p for p in data.get('vulnerable_configuration', []) if 'product' in p]
                }
                return {"source": "CIRCL", "results": circl_result}
        return []
    except Exception as e:
        print(f"[ERROR] Failed to query CIRCL for {cve_id}: {e}")
        return []

# Vulners Search Function
def search_vulners(cve_id):
    try:
        url = f"{VULNERS_API_BASE_URL}?query={cve_id}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("search", [])
            poc_links = [item.get('vhref') for item in data if 'exploit' in item.get('bulletinFamily', '').lower()]
            vulners_result = {
                "poc_links": poc_links
            }
            return {"source": "Vulners", "results": vulners_result}
        return []
    except Exception as e:
        print(f"[ERROR] Failed to query Vulners for {cve_id}: {e}")
        return []

# EPSS Search Function
def search_epss(cve_id):
    try:
        url = f"{EPSS_API_BASE_URL}?cve={cve_id}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json().get("data", [])
            if data:
                epss_result = {
                    "epss_score": data[0].get('epss', 'N/A'),
                    "percentile": data[0].get('percentile', 'N/A')
                }
                return {"source": "EPSS", "results": epss_result}
        return []
    except Exception as e:
        print(f"[ERROR] Failed to query EPSS for {cve_id}: {e}")
        return []

# Function to format severity based on CVSS score
def format_severity(cvss_score):
    try:
        cvss_score = float(cvss_score)
        if cvss_score >= 9.0:
            return Fore.RED + "Critical"
        elif cvss_score >= 7.0:
            return Fore.LIGHTRED_EX + "High"
        elif cvss_score >= 4.0:
            return Fore.YELLOW + "Medium"
        elif cvss_score > 0.0:
            return Fore.LIGHTYELLOW_EX + "Low"
    except (ValueError, TypeError):
        pass
    return Fore.WHITE + "Unknown"

# Function to display results grouped by source
def display_results_by_source(all_results):
    for source_results in all_results:
        source = source_results["source"]
        results = source_results["results"]
        print(Fore.LIGHTBLUE_EX + f"\n[INFO] Results from {source}:")
        if not results:
            print(f"[INFO] No results found in {source}.")
        else:
            if "summary" in results:
                print(Fore.WHITE + f"Summary: {results.get('summary')}")
            if "cvss_score" in results:
                severity = format_severity(results.get('cvss_score', 0))
                print(Fore.WHITE + f"CVSS Score: {results.get('cvss_score', 'N/A')} ({severity})")
            if "products" in results and results.get('products'):
                product_list = [p for p in results.get('products') if p != 'Unknown product']  # Filter out 'Unknown product'
                print(Fore.WHITE + f"Products Affected: {', '.join(product_list[:10])}")  # Limit to 10 products
            if "poc_links" in results and results.get('poc_links'):
                print(Fore.WHITE + f"POC Links: {', '.join(results.get('poc_links', ['N/A']))}")
            print(Fore.CYAN + "-" * 80)

# Aggregating search results
def search_all(cve_id, max_results, api_key=None):
    all_results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(search_nvd, cve_id, api_key),
            executor.submit(search_circl, cve_id),
            executor.submit(search_vulners, cve_id),
            executor.submit(search_epss, cve_id)
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                all_results.append(result)
    
    return all_results[:max_results]

# Main entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for CVE information across multiple sources.")
    parser.add_argument("cve_id", help="The CVE ID to search for (e.g., CVE-2023-22527)")
    parser.add_argument("-m", "--max-results", type=int, default=DEFAULT_RESULTS_DISPLAY, help="Max results to display (default: 5, max: 10)")
    
    args = parser.parse_args()
    cve_id = args.cve_id
    max_results = min(args.max_results, MAX_RESULTS_DISPLAY)

    # Display tool name
    display_tool_name()

    # Perform the search
    print(f"[INFO] Querying for {cve_id}...")
    all_results = search_all(cve_id, max_results)
    display_results_by_source(all_results)
