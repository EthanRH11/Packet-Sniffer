import shodan
import mysql.connector

#Shodan API Key
SHODAN_API_KEY = 'slee2NuPwHKBL59TMFOYx1bXEzDbwVIG'

api = shodan.Shodan(SHODAN_API_KEY)

#Connect to mySQL
db = mysql.connector.Connect(
    host = "localhost",
    user = "ehicks12",
    password = "eLLaMae05!!",
    database = "vulnerabilities_db"
)
cursor = db.cursor()

def search_shodan(query):
    try:
        result = api.search(query)
        for service in result['matches']:
            ip = service['ip_str']
            port = service['port']
            protocol = service['transport']
            vulnerabilities = service.get('vulns', {})

            # Insert vulnerabilities into MySQL database
            for vuln_id, vuln_data in vulnerabilities.items():
                description = vuln_data.get('description', 'No description available')
                severity = vuln_data.get('severity', 'Unknown')

                cursor.execute("""
                    INSERT INTO vulnerabilities (ip_address, port, protocol, vulnerability_id, vulnerability_description, severity)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (ip, port, protocol, vuln_id, description, severity))
                db.commit()

            print(f"Data for IP {ip} inserted.")
    except shodan.APIError as e:
        print(f"Error: {e}")

# Example query to search for HTTP services
search_shodan('port:80')