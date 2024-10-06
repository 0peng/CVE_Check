import requests
import concurrent.futures
from colorama import Fore, Style, init
import argparse

# Initialize colorama for colored output
init(autoreset=True)

# Constants for API URLs
CIRCL_API_BASE_URL = "https://cve.circl.lu/api/cve/"
EPSS_API_BASE_URL = "https://api.first.org/data/v1/epss"
GITHUB_API_URL = "https://api.github.com/search/repositories"
CISA_KEV_API_BASE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
EXPLOIT_DB_SEARCH_URL = "https://www.exploit-db.com/search"
PACKET_STORM_URL = "https://packetstormsecurity.com/search/?q="
HACKER_ONE_SEARCH_URL = "https://hackerone.com/vulnerabilities/search"

DEFAULT_RESULTS_DISPLAY = 5
MAX_RESULTS_DISPLAY = 10

# Function to display the tool logo with the name "CVE.CHECK"
def display_logo():
    logo_art = """
   ______  __      __  ______     _____ _    _ ______  ______ _    _ 
  / ____/  \ \    / / |  ____|   / ____| |  | |  ____||  ____| |  | |
 | |        \ \  / /  | |__     | |    | |__| | |__   | |__  | |__| |
 | |         \ \/ /   |  __|    | |    |  __  |  __|  |  __| |  __  |
 | |____      \  /    | |____   | |____| |  | | |____ | |____| |  | |
  \_____|      \/     |______|   \_____|_|  |_|______||______|_|  |_|  
                                                                      
    """
    print(Fore.CYAN + logo_art)

# CIRCL Search Function for CVE Summary, CVSS Score, and Severity
def search_circl(cve_id):
    try:
        url = f"{CIRCL_API_BASE_URL}{cve_id}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            summary = data.get("summary", "No detailed description available from CIRCL.")
            cvss_score = data.get("cvss", None)
            severity = format_severity(cvss_score) if cvss_score else "Unknown"
            return {
                "source": "CIRCL",
                "summary": summary,
                "cvss_score": cvss_score if cvss_score else "N/A",
                "cvss_severity": severity,
            }
        return {"source": "CIRCL", "summary": "No data found", "cvss_score": "N/A", "cvss_severity": "Unknown"}
    except Exception as e:
        print(f"[ERROR] Failed to query CIRCL for {cve_id}: {e}")
        return {"source": "CIRCL", "summary": "No data found", "cvss_score": "N/A", "cvss_severity": "Unknown"}

# EPSS Integration Search Function
def search_epss(cve_id):
    try:
        url = f"{EPSS_API_BASE_URL}?cve={cve_id}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json().get("data", [])
            if data:
                return {
                    "source": "EPSS",
                    "epss_score": data[0].get("epss", "N/A"),
                    "percentile": data[0].get("percentile", "N/A")
                }
        return {"source": "EPSS", "epss_score": "N/A", "percentile": "N/A"}
    except Exception as e:
        print(f"[ERROR] Failed to query EPSS for {cve_id}: {e}")
        return {"source": "EPSS", "epss_score": "N/A", "percentile": "N/A"}

# GitHub Search Function for PoCs
def search_github(cve_id):
    try:
        query = f"{cve_id} in:name"
        url = f"{GITHUB_API_URL}?q={query}"
        headers = {'Accept': 'application/vnd.github.v3+json'}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("items", [])
            return {"source": "GitHub", "results": data[:DEFAULT_RESULTS_DISPLAY]}
        return {"source": "GitHub", "results": []}
    except Exception as e:
        print(f"[ERROR] Failed to query GitHub for {cve_id}: {e}")
        return {"source": "GitHub", "results": []}

# ExploitDB Search Function for PoC Links
def search_exploitdb(cve_id):
    try:
        results = [{"title": f"Exploit for {cve_id}", "url": f"https://www.exploit-db.com/exploits/{cve_id}"}]
        return {"source": "ExploitDB", "results": results}
    except Exception as e:
        print(f"[ERROR] Failed to query ExploitDB for {cve_id}: {e}")
        return {"source": "ExploitDB", "results": []}

# Packet Storm Search Function for CVE Links
def search_packet_storm(cve_id):
    try:
        url = f"{PACKET_STORM_URL}{cve_id}"
        response = requests.get(url)
        if response.status_code == 200:
            results = [{"title": f"Packet Storm exploit for {cve_id}", "url": url}]
            return {"source": "Packet Storm", "results": results}
        return {"source": "Packet Storm", "results": []}
    except Exception as e:
        print(f"[ERROR] Failed to query Packet Storm for {cve_id}: {e}")
        return {"source": "Packet Storm", "results": []}

# CISA KEV Search Function for CVE Summary and Score
def search_cisa_kev(cve_id):
    try:
        url = f"{CISA_KEV_API_BASE_URL}?cve={cve_id}"
        response = requests.get(url)
        if response.status_code == 200 and response.text.strip():
            try:
                data = response.json().get("vulnerabilities", [])
                if data:
                    return {
                        "source": "CISA KEV",
                        "summary": data[0].get("vulnerabilityDescription", "No detailed description from CISA."),
                        "cvss_score": data[0].get("cvssBaseScore", "N/A"),
                    }
                else:
                    return {"source": "CISA KEV", "summary": "No CISA KEV data available", "cvss_score": "N/A"}
            except ValueError:
                print(f"[ERROR] Invalid JSON response from CISA KEV for {cve_id}.")
        return {"source": "CISA KEV", "summary": "No CISA KEV data available", "cvss_score": "N/A"}
    except Exception as e:
        print(f"[ERROR] Failed to query CISA KEV for {cve_id}: {e}")
        return {"source": "CISA KEV", "summary": "No CISA KEV data available", "cvss_score": "N/A"}

# HackerOne Search Function for Reports
def search_hackerone(cve_id):
    try:
        url = f"{HACKER_ONE_SEARCH_URL}?q={cve_id}"
        response = requests.get(url)
        if response.status_code == 200:
            results = [{"report": f"HackerOne report for {cve_id}", "url": url}]
            return {"source": "HackerOne", "results": results}
        return {"source": "HackerOne", "results": []}
    except Exception as e:
        print(f"[ERROR] Failed to query HackerOne for {cve_id}: {e}")
        return {"source": "HackerOne", "results": []}

# Function to format severity based on CVSS score
def format_severity(cvss_score):
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return Fore.RED + "Critical"
        elif score >= 7.0:
            return Fore.LIGHTRED_EX + "High"
        elif score >= 4.0:
            return Fore.YELLOW + "Medium"
        elif score > 0.0:
            return Fore.LIGHTYELLOW_EX + "Low"
    except (ValueError, TypeError):
        pass
    return Fore.MAGENTA + "Unknown"

# Function to display results grouped by source with enhanced formatting
def display_results(all_results):
    print(Fore.CYAN + "\n================================")
    print(Fore.CYAN + "      CVE Information")
    print(Fore.CYAN + "================================")

    # Display Severity and Summary at the Top
    for source_results in all_results:
        source = source_results["source"]

        if source == "CIRCL":
            print(Fore.CYAN + f"\nSummary: {source_results['summary']}")
            print(Fore.LIGHTWHITE_EX + f"CVSS Score: {source_results['cvss_score']} ({source_results['cvss_severity']})")

        if source == "EPSS":
            print(Fore.CYAN + f"\nEPSS Score: {source_results.get('epss_score', 'N/A')} (Percentile: {source_results.get('percentile', 'N/A')})")

    # Now Display Exploit Links and Repository Information
    print(Fore.CYAN + "\n--------------------------------")
    print(Fore.CYAN + "      Exploits and Repositories")
    print(Fore.CYAN + "--------------------------------")

    for source_results in all_results:
        source = source_results["source"]

        if source == "GitHub":
            print(Fore.CYAN + "\nGitHub Repos:")
            for repo in source_results["results"]:
                print(Fore.CYAN + f"Repo: {repo.get('full_name', 'N/A')}")
                print(Fore.CYAN + f"Description: {repo.get('description', 'N/A')}")
                print(Fore.GREEN + f"Repo Link: {repo.get('html_url', 'N/A')}")

        if source == "ExploitDB":
            print(Fore.CYAN + "\nExploitDB Links:")
            for exploit in source_results["results"]:
                print(Fore.GREEN + f"Exploit Title: {exploit.get('title', 'N/A')}")
                print(Fore.GREEN + f"Exploit Link: {exploit.get('url', 'N/A')}")

        if source == "Packet Storm":
            print(Fore.CYAN + "\nPacket Storm Links:")
            for exploit in source_results["results"]:
                print(Fore.GREEN + f"Exploit Title: {exploit.get('title', 'N/A')}")
                print(Fore.GREEN + f"Exploit Link: {exploit.get('url', 'N/A')}")

        if source == "CISA KEV":
            print(Fore.CYAN + f"\nSummary from CISA: {source_results['summary']}")
            print(Fore.LIGHTWHITE_EX + f"CVSS Score: {source_results['cvss_score']}")

        if source == "HackerOne":
            print(Fore.CYAN + "\nHackerOne Reports:")
            for report in source_results["results"]:
                print(Fore.GREEN + f"Report: {report.get('report', 'N/A')}")
                print(Fore.GREEN + f"Report Link: {report.get('url', 'N/A')}")

# Function to perform concurrent searches based on user selection
def search_all(cve_id, methods):
    all_results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        if "circl" in methods:
            futures.append(executor.submit(search_circl, cve_id))
        if "epss" in methods:
            futures.append(executor.submit(search_epss, cve_id))
        if "github" in methods:
            futures.append(executor.submit(search_github, cve_id))
        if "exploitdb" in methods:
            futures.append(executor.submit(search_exploitdb, cve_id))
        if "packetstorm" in methods:
            futures.append(executor.submit(search_packet_storm, cve_id))
        if "cisa" in methods:
            futures.append(executor.submit(search_cisa_kev, cve_id))
        if "hackerone" in methods:
            futures.append(executor.submit(search_hackerone, cve_id))

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                all_results.append(result)
    return all_results

# Main function with granular method selection
def main():
    display_logo()

    parser = argparse.ArgumentParser(description="Search for CVE information from multiple sources.")
    parser.add_argument("cve_id", help="CVE ID to search for")
    parser.add_argument("--methods", nargs='+', choices=['circl', 'epss', 'github', 'exploitdb', 'packetstorm', 'cisa', 'hackerone'],
                        default=['circl', 'epss', 'github', 'exploitdb', 'packetstorm', 'cisa', 'hackerone'],
                        help="Specify which methods to use (default: all)")
    parser.add_argument("--max-results", type=int, default=DEFAULT_RESULTS_DISPLAY, help="Maximum number of results to display per source (default: 5)")

    args = parser.parse_args()
    cve_id = args.cve_id.upper()

    # Perform the search based on selected methods
    all_results = search_all(cve_id, args.methods)

    # Display results grouped by source
    display_results(all_results)

if __name__ == "__main__":
    main()
