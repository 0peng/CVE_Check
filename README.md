# CVE.CHECK - Vulnerability Information and Exploit Aggregator


      ______  __      __  ______     _____ _    _ ______  ______ _    
  / ____/  \ \    / / |  ____|   / ____| |  | |  ____||  ____| |  | |
 | |        \ \  / /  | |__     | |    | |__| | |__   | |__  | |__| |
 | |         \ \/ /   |  __|    | |    |  __  |  __|  |  __| |  __  |
 | |____      \  /    | |____   | |____| |  | | |____ | |____| |  | |
  \_____|      \/     |______|   \_____|_|  |_|______||______|_|  |_|  




# CVE.CHECK is a Python-based tool designed to fetch and aggregate critical information about vulnerabilities from multiple sources. The tool helps security analysts, researchers, and engineers quickly gather CVE information, exploit details, and other relevant reports in a single tool

# It aggregates data from multiple sources, including exploit links, CVSS scores, vulnerability summaries, publication dates, and proof of concept (PoC) details (if available).

## 🛡️Features:

**CVE Information Retrieval:** Retrieves CVE details such as descriptions, CVSS score, severity, and more from the CIRCL API and other sources.

**EPSS Integration:** Provides exploit prediction scoring from the Exploit Prediction Scoring System (EPSS) API. This gives insights into the likelihood of exploitation, helping prioritize vulnerabilities.

**Public Exploits Aggregation:** Gathers publicly available proof-of-concept (PoC) exploits from multiple sources like:

**GitHub:** Fetches PoC repositories related to the CVE.

**ExploitDB:** Fetches exploit information from the ExploitDB database.

**Packet Storm:** Fetches exploit information from the Packet Storm database.

**CISA KEV:** Shows if the CVE has been listed in the Known Exploited Vulnerabilities (KEV) list by CISA. If listed, it provides direct links to CISA references.

**HackerOne Reports:** Retrieves reports related to the CVE from HackerOne, indicating whether the vulnerability was used in bug bounty programs and what severity level it held.

**User-Friendly Interface:** Clean and readable output with color-coded severity, summary, and exploit links for easier identification and prioritization.


          +--------------------+
          | User provides CVE ID|
          +---------+----------+
                    |
                    v
      +-------------+-------------+
      |  Fetch CVE Details         | (from CIRCL or other API sources)
      +-------------+-------------+
                    |
                    v
+--------------------+------------------+
| Fetch EPSS Score                       | (from EPSS API)
+--------------------+------------------+
                    |
                    v
+--------------------+------------------+
| Fetch Exploit Data                      | (from GitHub, ExploitDB, PacketStorm)
+--------------------+------------------+
                    |
                    v
+--------------------+------------------+
| Fetch CISA KEV Status                   | (Check if CVE is in CISA KEV list)
+--------------------+------------------+
                    |
                    v
+--------------------+------------------+
| Fetch HackerOne Reports                | (If any reports are available)
+--------------------+------------------+
                    |
                    v
        +-----------+----------+
        | Display Results       |
        +----------------------+



**To run CVE.CHECK, ensure that the following dependencies are installed
**

## Prerequisites:
Python 3.x: Make sure you have Python 3.6+ installed.
PIP: Ensure that Python's package manager, pip, is installed.

- **Dependencies**:
requests: For making HTTP API requests.
colorama: For colorizing terminal output.
argparse: For handling command-line arguments.


### Usage

1-Search by CVE ID: You can search by CVE ID to retrieve the most detailed information for a specific CVE.

python3 CVE.py CVE-xxxx-xxxx



## TODO: 2-Search by Product Name: You can search by the product name to retrieve vulnerabilities associated with that product.

python3 CVE.py -p "product"


### Contribution
Feel free to submit pull requests or open issues to improve this tool. We welcome all contributions to make this tool even better.

