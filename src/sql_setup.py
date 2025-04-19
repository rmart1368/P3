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
    # go through all files
    for root, _, files in os.walk(EXTERNAL):
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
    vendor = ""
    product = ""
    platform = ""
    if affected:
        vendor = affected[0].get("vendor", "n/a")
        product = affected[0].get("product", "n/a")
        platform = affected[0].get("platforms", "n/a")
    
    # severity info
    severity = ""
    severity_score = ""
    metrics = cna.get("metrics", [])
    if metrics: 
        cvss = metrics[0].get("cvssV3_1", {})
        severity = cvss.get("baseSeverity", "n/a")
        severity_score = cvss.get("baseScore", "n/a")

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

# Function to query 