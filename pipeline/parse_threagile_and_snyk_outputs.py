import sys
import pandas as pd
import json
from datetime import date
import warnings
import requests
from bs4 import BeautifulSoup
from xhtml2pdf import pisa
warnings.filterwarnings("ignore")

def extract_threagile(filename):
    df = pd.read_excel(filename)
    return set(zip(df["CWE"], df["Severity"], df["STRIDE"] , df["Risk Category"]))

def extract_snyk(filename):
    cwes = []
    with open(filename, encoding='utf-8') as f:
        data = json.load(f)

        for vuln in data["vulnerabilities"]:
            for ids in vuln["identifiers"].items():
                if (ids[0] == 'CWE'):
                    cwes.append((ids[1][0], vuln['severity'], vuln['from'], vuln['version'], vuln['packageName']))
    return cwes
    
def generate_report():
    if len(sys.argv) != 3:
        print("Usage: python extract_cwe_from_threagile_report.py [PATH-TO-SNYK-JSON] [PATH-TO-THREAGILE-XLSX]")
    
    snyk_file, threagile_file = sys.argv[1:]
    snyk_cwe = extract_snyk(snyk_file)
    threagile_cwe = extract_threagile(threagile_file)

    html_header = '''<!DOCTYPE html>
<html>
<head>
<style>
table {
  font-family: arial, sans-serif;
  border-collapse: collapse;
  width: 100%;
}

td, th {
  border: 1px solid #dddddd;
  text-align: left;
  padding: 8px;
}

</style>
</head>

<body>
'''

    table_header = '''  <table>
    <tr>
      <th style="width: 15%">CWE</th>
      <th style="width: 35%">Description</th>
      <th style="width: 15%">Severity</th>
      <th style="width: 35%"> More Info</th>
    </tr>
'''
    with open("threatmodel_report.html", "a") as f:
        f.write(html_header)
        f.write(' <h2>Threagile CWE Table</h2>\n')
        f.write(table_header)
        for cwe in threagile_cwe:
            vuln_cwe, vuln_severity, vuln_stride, vuln_risks = cwe
            cwe_number = vuln_cwe.split('-')[-1]
            link = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
            page = requests.get(link).text

            if vuln_severity == 'Critical':
                color = 'red'
            elif vuln_severity == 'Elevated':
                color = 'orange'
            elif vuln_severity == "Medium":
                color = 'brown'
            elif vuln_severity == "Low":
                color = 'green'

            f.write('   <tr>\n')
            f.write(f'      <td><a style="color:{color}; font-weight:bold" href={link}>{cwe[0]}</a></td>\n')
            f.write(f'      <td style="color:{color}">{str(BeautifulSoup(page, "html.parser").find("h2")).split(">")[1].split("<")[0]}</td>\n')
            f.write(f'      <td style="color:{color}">{vuln_severity}</td>\n')
            f.write(f'      <td><b>Stride: </b>{vuln_stride} <br> <b>Risk Category: </b>{vuln_risks}</td>\n')
            f.write('   </tr>\n')
        f.write(' </table>\n')
    
    with open("threatmodel_report.html", "a") as f:
        f.write('\n <h2>Snyk CWE Table</h2>\n')
        f.write(table_header)
        for cwe in snyk_cwe:
            vuln_cwe, vuln_severity, vuln_from, vuln_version, vuln_packageName = cwe
            cwe_number = vuln_cwe.split('-')[-1]
            link = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"
            page = requests.get(link).text

            vuln_severity = vuln_severity.title()
            if vuln_severity == 'Low':
                color = 'green'
            elif vuln_severity == 'High':
                color = 'red'
            elif vuln_severity == "Medium":
                color = 'orange'

            f.write('   <tr>\n')
            f.write(f'      <td><a style="color:{color}; font-weight:bold" href={link}>{cwe[0]}</a></td>\n')
            f.write(f'      <td style="color:{color}">{str(BeautifulSoup(page, "html.parser").find("h2")).split(">")[1].split("<")[0]}</td>\n')
            f.write(f'      <td style="color:{color}">{vuln_severity}</td>\n')
            f.write(f'      <td><b>From: </b>{" ".join(vuln_from)}<br> <b>Version: </b>{vuln_version} <br> <b>Package Name: </b>{vuln_packageName}</td>\n')
            f.write('   </tr>\n')
        f.write(' </table>\n')
        f.write('</body>\n')
        f.write('</html>')
    
    with open('threatmodel_report.html') as source_html:
        with open('Findings_Summary.pdf', "w+b") as result_file: 
        # convert HTML to PDF
            pisa.CreatePDF(source_html, dest=result_file)           # file handle to recieve result

if __name__ == '__main__':
    generate_report()