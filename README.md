# CVE_Check
CVE Check Tool is an advanced utility designed to search for and display detailed information about CVEs (Common Vulnerabilities and Exposures) across multiple trusted sources like NVD, CIRCL, Vulners, and EPSS. 

The tool is flexible and allows users to either search for a specific CVE by ID or search for vulnerabilities associated with a particular product (e.g., Apache Tomcat or Cisco XE). 

It aggregates data from multiple sources, including exploit links, CVSS scores, vulnerability summaries, publication dates, and proof of concept (PoC) details (if available).

                  +-----------------------+
                  |  User Input (CVE ID)  |
                  +-----------------------+
                             |
                             v
        +----------------------------+      +---------------------+
        |  Query NVD API              |<---->|  Query CIRCL API    |
        +----------------------------+      +---------------------+
                             |                            |
                             v                            |
        +----------------------------+                   |
        |  Query Vulners API           |<----------------+
        +----------------------------+
                             |
                             v
        +----------------------------+
        |  Aggregated Results         |
        +----------------------------+


### Requirements
Before using the CVE Check tool, the following must be installed on your system:

### Requirements
- **Python 3.x**: This tool is built using Python 3.x.
- **Dependencies**:
  - `requests`
  - `colorama`
  - `concurrent.futures`


### Usage

1-Search by CVE ID: You can search by CVE ID to retrieve the most detailed information for a specific CVE.

python3 CVE.py CVE-xxxx-xxxx

2-Search by Product Name: You can search by the product name to retrieve vulnerabilities associated with that product.

python3 CVE.py -p "product"


### Contribution
Feel free to submit pull requests or open issues to improve this tool. We welcome all contributions to make this tool even better.

