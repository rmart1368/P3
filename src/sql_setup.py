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
BASE = os.path.abspath(os.path.join(os.path.dirname(__file__, '..')))
DB_FILE = os.path.join(BASE, 'internal_cve_db.sqlite')
EXTERNAL = os.path.join(BASE, 'cve_db', 'external_cve_db')

# Function to set up 
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
        description    TEXT,
        published_date TEXT,
        year           INTEGER,
        os             TEXT,
        software       TEXT,
        version        TEXT,
        severity       TEXT,
        cvss           REAL
      );
    """)
    conn.commit()
    return conn, cur

#def load_all_cves()