import requests
import json
import pandas as pd
from openpyxl import Workbook
from openpyxl.utils.dataframe import dataframe_to_rows
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import textwrap

# Define the ANSI color codes
reset = '\033[0m'  # Reset
cyan = '\033[36m'  # Cyan
magenta = '\033[35m'  # Magenta
yellow = '\033[33m'  # Yellow
green = '\033[32m'  # Green

# Banner
def print_banner():
    print(f"{cyan} Threat Analysis Tool by: Dark_Shadow04 {reset}\n")
    print(f"{yellow} https://github.com/DarkShadow04  {reset}\n")
    print(f"{magenta} Copyright 2023 Dark_Shadow04 {reset}\n")

# Function to make API requests to AbuseIPDB
def query_abuseipdb(api_key, ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {'Key': api_key, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    return response.json()

# Function to create PDF report
def create_pdf_report(results):
    print("\n[GENERATE PDF REPORT]\n")
    pdf_path = "threat_report.pdf"
    print("Results for PDF report:")
    print(results)  # Print results to verify
    try:
        c = canvas.Canvas(pdf_path, pagesize=letter)
        c.drawString(100, 750, "Threat Report")
        c.drawString(100, 730, "--------------------------")
        y = 700
        for result in results:
            if y < 150:  # Check if there's enough space for another entry
                c.showPage()  # Create a new page if there's not enough space
                c.drawString(100, 750, "Threat Report")
                c.drawString(100, 730, "--------------------------")
                y = 700
            c.drawString(100, y, f"IP: {result['ip']}")
            c.drawString(300, y, f"Abuse Confidence Score: {result['abuseConfidenceScore']}")
            c.drawString(100, y - 20, f"Country Code: {result['countryCode']}")
            c.drawString(300, y - 20, f"Usage Type: {result['usageType']}")
            c.drawString(100, y - 40, f"ISP: {result['isp']}")
            c.drawString(300, y - 40, f"Total Reports: {result['totalReports']}")
            c.drawString(100, y - 60, f"Number of Distinct Users: {result['numDistinctUsers']}")
            c.drawString(300, y - 60, f"Last Reported At: {result['lastReportedAt']}")
            y -= 100  # Adjust the y-coordinate for spacing
            y -= 20  # Add extra space between different targets
        c.save()
        print(f"PDF report generated at: {pdf_path}")
    except Exception as e:
        print(f"Error generating PDF report: {e}")

# Function to create Excel report
def create_excel_report(results):
    print("\n[GENERATE EXCEL REPORT]\n")
    excel_path = "threat_report.xlsx"
    print("Results for Excel report:")
    print(results)  # Print results to verify
    try:
        wb = Workbook()
        ws = wb.active
        ws.append(['IP', 'Abuse Confidence Score', 'Country Code', 'Usage Type', 'ISP', 'Total Reports', 'Number of Distinct Users', 'Last Reported At'])
        for result in results:
            ws.append([
                result['ip'],
                result['abuseConfidenceScore'],
                result['countryCode'],
                result['usageType'],
                result['isp'],
                result['totalReports'],
                result['numDistinctUsers'],
                result['lastReportedAt']
            ])
        wb.save(excel_path)
        print(f"Excel report generated at: {excel_path}")
    except Exception as e:
        print(f"Error generating Excel report: {e}")

# Main function
def main():
    print_banner()
    print(f"{green}Welcome to the Threat Analysis Tool using AbuseIPDB API.{reset}")
    # Ask user whether to edit existing API keys
    edit_keys = input("Do you want to edit existing API keys? (yes/no): ").lower() == 'yes'
    if edit_keys:
        api_key = input("Enter new API key for AbuseIPDB: ")
    else:
        api_key = "39e882eb5a31fd6bbc8bdf14eb8783b0a0622459d9d6622a68d83ea80385ee05c78a471dfc64a51e"
    
    # Initialize results list
    results = []

    # Start console
    while True:
        print("\nOptions:")
        print("1. Analyze IP")
        print("2. Analyze File")
        print("3. Generate Report")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            print("\n[ANALYZE IP]\n")
            ip = input("Enter IP address: ")
            result = query_abuseipdb(api_key, ip)
            results.append({
                'ip': ip,
                'abuseConfidenceScore': result['data']['abuseConfidenceScore'],
                'countryCode': result['data']['countryCode'],
                'usageType': result['data']['usageType'],
                'isp': result['data']['isp'],
                'totalReports': result['data']['totalReports'],
                'numDistinctUsers': result['data']['numDistinctUsers'],
                'lastReportedAt': result['data']['lastReportedAt']
            })
            print(json.dumps(result, indent=4))  # Print result to terminal
        elif choice == '2':
            print("\n[ANALYZE FILE]\n")
            file_path = input("Enter path to the file containing list of IP addresses: ")
            with open(file_path, 'r') as file:
                ips = file.readlines()
                for ip in ips:
                    ip = ip.strip()
                    result = query_abuseipdb(api_key, ip)
                    results.append({
                        'ip': ip,
                        'abuseConfidenceScore': result['data']['abuseConfidenceScore'],
                        'countryCode': result['data']['countryCode'],
                        'usageType': result['data']['usageType'],
                        'isp': result['data']['isp'],
                        'totalReports': result['data']['totalReports'],
                        'numDistinctUsers': result['data']['numDistinctUsers'],
                        'lastReportedAt': result['data']['lastReportedAt']
                    })
                    print(json.dumps(result, indent=4))  # Print result to terminal
        elif choice == '3':
            if not results:
                print("No results to generate report.")
            else:
                report_format = input("Enter report format (pdf/xlsx): ").lower()
                if report_format == 'pdf':
                    create_pdf_report(results)
                elif report_format == 'xlsx':
                    create_excel_report(results)
                else:
                    print("Invalid report format.")
        elif choice == '4':
            print(f"{green}Exiting from 'Dark_Shadow04' private database console.{reset}")
            break
        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()
