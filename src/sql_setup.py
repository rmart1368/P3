# This file is for the SQL setup

'''
Game Plan: 
    1. Access the external database through the submodule 
    2. Move the data into SQLite
'''

'''
Bash Commands run:
    # Create and activate the virtual environment
    1. python3 -m venv .venv
    2. source .venv/bin/activate

    #install
    pip install -r src/requirements.txt
'''

import os, sqlite3, json

# Path declarations 
BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_FILE = os.path.join(BASE, 'internal_cve_db.sqlite')
EXTERNAL = os.path.join(BASE, 'cve_db', 'external_cve_db')
OUTPUT_TXT = os.path.join(BASE, 'cve_export.txt')

# Function to set up table
def get_db_cursor():
    # create connection and cursor
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    # enable WAL
    cur.execute("PRAGMA journal_mode = WAL;")
    # build table
    cur.execute("""
      CREATE TABLE IF NOT EXISTS cves (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id         TEXT UNIQUE,
        published_date TEXT,
        description    TEXT,
        vendor         TEXT,
        product        TEXT,
        os             TEXT,
        severity       TEXT,
        severity_score REAL
      );
    """)
    conn.commit()
    return conn, cur

# Function to search through external cve database
def load_cves():
    # go through all files in cves dir
    cves_dir = os.path.join(EXTERNAL, 'cves')

    for root, _, files in os.walk(cves_dir):
        for file in files:
            # check to make sure it is a .json file
            if not file.lower().endswith('.json'):
                continue
            # build path, open file, load data 
            path = os.path.join(root, file)
            # dev note: using 'with' will close the file automatically, no need to worry about closing it manually
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # check if data is a dictionary, and yields accordingly
            if isinstance(data, dict):
                yield data
            else:
                yield from data

# Function to format data properly
# dev note: the json file is too complex and nested, we need to get just the necessary info out before working with it
def parse_cve(entry):
    # cve entry metadata 
    meta = entry.get("cveMetadata", {})
    # information provided by CNA (CVE Numbering Authority), this is the most reliable one to use
    cna = entry.get("containers", {}).get("cna", {})

    cve_id  = meta.get("cveId")
        
    # we only want YYYY-MM-DD
    pub_date = meta.get("datePublished", "n/a")[:10]
    
    # english-only description
    description = ""
    for d in cna.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "n/a")
            break
    
    # software info
    affected = cna.get("affected", [])
    vendor = "n/a"
    product = "n/a"
    platform = "n/a"
    if affected:
        vendor = affected[0].get("vendor", "n/a")
        product = affected[0].get("product", "n/a")
        pre_platform = affected[0].get("platforms", [])
        if isinstance(pre_platform, list):
            platform = ", ".join(pre_platform).strip() or "n/a"
        else:
            platform = str(pre_platform).strip() or "n/a"
    
    # severity info
    severity = ""
    severity_score = ""
    metrics_storage = cna.get("metrics", [{}])  # Default to [{}] if "metrics" is empty or missing
    cvss_v3 = metrics_storage[0].get("cvssV3_1", {})  # Safely get cvssV3_1, default to {} if not found
    severity = cvss_v3.get("baseSeverity", "n/a")
    severity_score = cvss_v3.get("baseScore", "n/a")
    
    return (
        cve_id, pub_date, description, vendor, product, platform, severity, severity_score
    )

# Function to import data
def import_cves():
    conn, cur = get_db_cursor()
    rows = []
    for entry in load_cves():
        rows.append(parse_cve(entry))

    cur.executemany("""
      INSERT OR IGNORE INTO cves
        (cve_id, published_date, description, vendor, product, os, severity, severity_score)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    conn.commit()
    conn.close()
    return len(rows)

# Function to query cve database with optional filters 
def query_cves(start_date = None, end_date = None, vendor = None, product = None, os_name = None):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    sql_parts = [
        "SELECT cve_id, published_date, vendor, product, os, severity, severity_score",
        "FROM cves",
        # dev note: don't remove this, it makes the filters easier to work with
        "WHERE 1=1"
    ]

    filters = []

    # append relevant filters to the query
    if vendor:
        sql_parts.append("AND vendor = ?")
        filters.append(vendor)
    if product:
        sql_parts.append("AND product = ?")
        filters.append(product)
    if os_name:
        sql_parts.append("AND os = ?")
        filters.append(os_name)
    if start_date:
        sql_parts.append("AND published_date >= ?")
        filters.append(start_date)
    if end_date:
        sql_parts.append("AND published_date <= ?")
        filters.append(end_date)

    # place actual values into the query and get all the results
    sql_query = " ".join(sql_parts)
    cur.execute(sql_query, filters)
    results = cur.fetchall()

    conn.close()
    return results

def export_to_txt(cve_rows):
    with open(OUTPUT_TXT, 'w', encoding='utf-8') as f:
        for row in cve_rows:
            line = "\t".join(str(item).replace('\n', ' ').replace('\t', ' ') for item in row)
            f.write(line + "\n")
        print(f"Exported {len(cve_rows)} CVEs to {OUTPUT_TXT}")

if __name__ == '__main__':
    count = import_cves()
    all_rows = query_cves()
    valid_rows = [row for row in all_rows if row[0] and not str(row[0]).startswith("None")]
    export_to_txt(valid_rows)
