import requests
import sqlite3
import json

#API Key from NVD
API_KEY = "30348d47-41cb-4018-86a0-df81b15b4db6"

#SQLite Database
DB_NAME = "vulnerabilities.db"

def fetch_vulnerabilities():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey" : API_KEY}
    params = {"resultsPerPage": 100}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Unable to fetch data. Status Code {response.status_code}")
        return None

#Create database and table
def setup_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id TEXT PRIMARY KEY,
            description TEXT,
            port INTEGER
        )
    ''')
    conn.commit()
    conn.close()

#Parse and insert vulnerabilities into the database
def insert_vulns(vuln_data):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    for item in vuln_data.get("Vulnerabilities", []):
        cve_id = item ["cve"]["id"]
        description = item ["cve"]["descriptions"][0]["value"]

        port = None
        if "port 21" in description.lower():
            port = 21
        elif "port 80" in description.lower():
            port = 80

        cursor.execute('''
            INSERT OR IGNORE INTO vulnerabilities (cve_id, description, port)
            VALUES (?, ?, ?)
        ''', (cve_id, description, port))

    conn.commit()
    conn.close()
    
if __name__ == "__main__":
    setup_database()
    data = fetch_vulnerabilities()
    if data:
        insert_vulns(data)
        print("Database updated successfully!")