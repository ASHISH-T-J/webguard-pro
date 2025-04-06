import json
from datetime import datetime

class ReportGenerator:
    def __init__(self, scanner):
        self.scanner = scanner

    def generate_json_report(self, report, filename):
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)

    def generate_html_report(self, report, filename):
        html_content = f"""
        <html>
            <head>
                <title>Scan Report - {self.scanner.domain}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
                    .vulnerability {{ background-color: #fff3f3; padding: 10px; margin: 10px 0; }}
                    table {{ width: 100%; border-collapse: collapse; }}
                    th, td {{ padding: 8px; text-align: left; border: 1px solid #ddd; }}
                    th {{ background-color: #f5f5f5; }}
                    .high {{ color: #d9534f; }}
                    .medium {{ color: #f0ad4e; }}
                    .low {{ color: #5bc0de; }}
                </style>
            </head>
            <body>
                <h1>Web Vulnerability Scan Report</h1>
                <div class="section">
                    <h2>Scan Summary</h2>
                    <p>Target Domain: {self.scanner.domain}</p>
                    <p>Scan Date: {report['scan_info']['scan_date']}</p>
                    <p>Total Subdomains: {report['scan_info']['total_subdomains']}</p>
                    <p>Live Hosts: {report['scan_info']['total_live_hosts']}</p>
                    <p>URLs Crawled: {report['scan_info']['total_urls_crawled']}</p>
                    <p>Vulnerabilities Found: {report['scan_info']['total_vulnerabilities']}</p>
                </div>
                
                <div class="section">
                    <h2>Vulnerabilities</h2>
                    {self._generate_vulnerability_table(report['vulnerabilities'])}
                </div>
                
                <div class="section">
                    <h2>Live Hosts</h2>
                    {self._generate_host_table(report['live_hosts'])}
                </div>
            </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)

    def _generate_vulnerability_table(self, vulnerabilities):
        if not vulnerabilities:
            return "<p>No vulnerabilities found.</p>"
            
        table = """
        <table>
            <tr>
                <th>Type</th>
                <th>URL</th>
                <th>Parameter</th>
                <th>Payload</th>
                <th>Confidence</th>
                <th>Timestamp</th>
            </tr>
        """
        
        for vuln in vulnerabilities:
            confidence_class = vuln.get('confidence', 'Medium').lower()
            table += f"""
            <tr>
                <td>{vuln['type']}</td>
                <td>{vuln['url']}</td>
                <td>{vuln['parameter']}</td>
                <td>{vuln['payload']}</td>
                <td class="{confidence_class}">{vuln.get('confidence', 'Medium')}</td>
                <td>{vuln['timestamp']}</td>
            </tr>
            """
        
        table += "</table>"
        return table

    def _generate_host_table(self, hosts):
        if not hosts:
            return "<p>No live hosts found.</p>"
            
        table = """
        <table>
            <tr>
                <th>URL</th>
                <th>Status Code</th>
                <th>Server</th>
                <th>Technologies</th>
            </tr>
        """
        
        for host in hosts:
            table += f"""
            <tr>
                <td>{host['url']}</td>
                <td>{host['status_code']}</td>
                <td>{host['server']}</td>
                <td>{', '.join(host['technologies'])}</td>
            </tr>
            """
        
        table += "</table>"
        return table
