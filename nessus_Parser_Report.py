#!/usr/bin/env python3

import argparse
import os
import datetime
import csv
from lxml import etree
import openpyxl
from openpyxl.styles import Alignment, Border, Side, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.chart import PieChart, Reference, BarChart

# --- Global Data Structures ---
# Using dictionaries and lists to replicate the complex data handling of the Perl script
hosts_data = []
vulnerability_summary = {}
ip_vuln_summary = {}
compliance_data = {}
recast_rules = {}

def parse_recast_file(recast_file):
    """Parses the vulnerability recast file."""
    try:
        with open(recast_file, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) == 3:
                    plugin_id, old_sev, new_sev = row
                    recast_rules[plugin_id] = {'old': int(old_sev), 'new': int(new_sev)}
        print(f"Successfully loaded {len(recast_rules)} recast rules from {recast_file}")
    except FileNotFoundError:
        print(f"Error: Recast file not found at {recast_file}")
        exit(1)
    except Exception as e:
        print(f"Error reading recast file: {e}")
        exit(1)

def normalize_and_extract_data(host_root, filename):
    """
    Parses a single ReportHost element, extracts all data, and stores it
    in a structured dictionary, similar to the Perl script's approach.
    """
    host_ip_elem = host_root.find('HostProperties/tag[@name="host-ip"]')
    if host_ip_elem is None:
        return
    
    host_ip = host_ip_elem.text
    
    host_dict = {
        'ip': host_ip,
        'filename': filename,
        'fqdn': host_root.findtext('HostProperties/tag[@name="host-fqdn"]', 'N/A'),
        'netbios_name': host_root.findtext('HostProperties/tag[@name="netbios-name"]', 'N/A'),
        'os': host_root.findtext('HostProperties/tag[@name="operating-system"]', 'N/A'),
        'mac_address': host_root.findtext('HostProperties/tag[@name="mac-address"]', 'N/A'),
        'local_checks_proto': host_root.findtext('HostProperties/tag[@name="local-checks-proto"]', 'N/A'),
        'vulnerabilities': [],
        'compliance_checks': [],
        'ports': set(),
        'info': {} # For storing extracted info like users, processes etc.
    }

    report_items = host_root.findall('ReportItem')
    
    for item in report_items:
        plugin_id = item.get('pluginID')
        severity = int(item.get('severity', 0))

        # Apply recast rules
        if plugin_id in recast_rules and recast_rules[plugin_id]['old'] == severity:
            severity = recast_rules[plugin_id]['new']

        cve_list = [c.text for c in item.findall('cve')]
        
        vuln_details = {
            'plugin_id': plugin_id,
            'plugin_name': item.get('pluginName'),
            'severity': severity,
            'port': item.get('port', '0'),
            'protocol': item.get('protocol', ''),
            'svc_name': item.get('svc_name', ''),
            'plugin_family': item.get('pluginFamily'),
            'synopsis': item.findtext('synopsis', ''),
            'description': item.findtext('description', ''),
            'solution': item.findtext('solution', ''),
            'plugin_output': item.findtext('plugin_output', ''),
            'cvss_base_score': item.findtext('cvss_base_score', 'N/A'),
            'cvss_vector': item.findtext('cvss_vector', 'N/A'),
            'cve': ', '.join(cve_list) if cve_list else 'N/A',
            'xref': ', '.join([x.text for x in item.findall('xref')])
        }
        
        # --- Detailed Plugin Parsing (from Perl script logic) ---
        if vuln_details['plugin_family'] == "Policy Compliance":
            # Handle Compliance Checks
            compliance_check = {
                'host_ip': host_ip,
                'plugin_id': plugin_id,
                'severity': severity,
                'audit_file': item.findtext('cm:compliance-audit-file', 'N/A'),
                'check_name': item.findtext('cm:compliance-check-name', 'N/A'),
                'result': item.findtext('cm:compliance-result', 'N/A'),
                'actual_value': item.findtext('cm:compliance-actual-value', 'N/A'),
                'policy_value': item.findtext('cm:compliance-policy-value', 'N/A'),
                'info': item.findtext('cm:compliance-info', 'N/A'),
                'solution': item.findtext('cm:compliance-solution', 'N/A'),
            }
            host_dict['compliance_checks'].append(compliance_check)
        elif plugin_id == '17651': # Password Policy
             output = vuln_details['plugin_output']
             if output:
                policy = {}
                for line in output.split('\n'):
                    if ':' in line:
                        key, val = line.split(':', 1)
                        policy[key.strip()] = val.strip()
                host_dict['info']['password_policy'] = policy
        else:
            host_dict['vulnerabilities'].append(vuln_details)
        
        # Populate port data
        if vuln_details['port'] != '0':
            host_dict['ports'].add((
                vuln_details['port'],
                vuln_details['protocol'],
                vuln_details['svc_name']
            ))

    hosts_data.append(host_dict)

def extract_vulnerabilities_for_compare(report_hosts):
    """Helper for comparison mode."""
    vulns = {}
    for host in report_hosts:
        host_ip = host.find('HostProperties/tag[@name="host-ip"]').text
        for item in host.findall('ReportItem'):
            if int(item.get('severity')) > 0: # Only compare actual vulnerabilities
                plugin_id = item.get('pluginID')
                port = item.get('port')
                protocol = item.get('protocol')
                key = f"{host_ip}-{plugin_id}-{port}-{protocol}"
                vulns[key] = {
                    'host_ip': host_ip,
                    'plugin_id': plugin_id,
                    'plugin_name': item.get('pluginName'),
                    'severity': int(item.get('severity')),
                    'port': port,
                    'protocol': protocol,
                }
    return vulns

def create_styles():
    """Create reusable styles for the workbook."""
    styles = {}
    header_font = Font(bold=True, color='FFFFFF')
    header_fill = PatternFill(start_color='4F81BD', end_color='4F81BD', fill_type='solid')
    thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))

    styles['header'] = {'font': header_font, 'fill': header_fill, 'border': thin_border, 'alignment': Alignment(horizontal='center', vertical='center', wrap_text=True)}
    styles['cell'] = {'border': thin_border, 'alignment': Alignment(horizontal='left', vertical='top', wrap_text=True)}
    styles['cell_center'] = {'border': thin_border, 'alignment': Alignment(horizontal='center', vertical='center')}
    
    styles['url'] = Font(color='0000FF', underline='single')

    severity_fills = {
        4: PatternFill(start_color='800000', end_color='800000', fill_type='solid'), # Critical (Dark Red)
        3: PatternFill(start_color='FF0000', end_color='FF0000', fill_type='solid'), # High (Red)
        2: PatternFill(start_color='FFA500', end_color='FFA500', fill_type='solid'), # Medium (Orange)
        1: PatternFill(start_color='FFFF00', end_color='FFFF00', fill_type='solid'), # Low (Yellow)
        0: PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')  # Info (Light Gray)
    }
    for sev, fill in severity_fills.items():
        styles[f'sev_{sev}'] = {'fill': fill, 'border': thin_border, 'alignment': Alignment(horizontal='left', vertical='top', wrap_text=True)}

    return styles

def apply_style(cell, style):
    """Apply a style dictionary to a cell."""
    for key, value in style.items():
        setattr(cell, key, value)

def set_headers_and_widths(ws, headers, widths):
    """Set headers and column widths for a worksheet."""
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num, value=header)
        apply_style(cell, STYLES['header'])
    for col_num, width in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(col_num)].width = width
    ws.freeze_panes = 'A2'

# --- Worksheet Creation Functions ---

def create_home_sheet(wb, summary_counts):
    ws = wb.active
    ws.title = "Home"
    
    ws.cell(row=1, column=1, value="Nessus Analysis Report").font = Font(bold=True, size=16)
    ws.cell(row=2, column=1, value=f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    ws.cell(row=4, column=1, value="Quick Links").font = Font(bold=True, underline='single')
    row = 5
    for sheet_name in wb.sheetnames:
        if sheet_name != "Home":
            cell = ws.cell(row=row, column=1, value=sheet_name)
            cell.hyperlink = f"#'{sheet_name}'!A1"
            cell.font = STYLES['url']
            row += 1

    ws.cell(row=row, column=1, value="Vulnerability Counts by Severity").font = Font(bold=True, underline='single')
    row += 1
    
    headers = ["Severity", "Count"]
    for i, header in enumerate(headers):
        ws.cell(row=row, column=i+1, value=header).font = Font(bold=True)
    
    sev_map = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
    chart_data_rows = []
    for sev_level, sev_name in sev_map.items():
        row += 1
        chart_data_rows.append(row)
        count = summary_counts['by_severity'].get(sev_level, 0)
        ws.cell(row=row, column=1, value=sev_name)
        ws.cell(row=row, column=2, value=count)

    # Pie Chart
    pie = PieChart()
    labels = Reference(ws, min_col=1, min_row=chart_data_rows[0], max_row=chart_data_rows[-1])
    data = Reference(ws, min_col=2, min_row=chart_data_rows[0]-1, max_row=chart_data_rows[-1])
    pie.add_data(data, titles_from_data=True)
    pie.set_categories(labels)
    pie.title = "Vulnerability Distribution"
    ws.add_chart(pie, "D4")

    ws.column_dimensions['A'].width = 30
    
def create_vulnerability_sheets(wb, hosts_data):
    sev_map = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}
    headers = ["Host IP", "FQDN", "OS", "Port", "Protocol", "Plugin ID", "Plugin Name", "Synopsis", "Solution", "CVEs", "CVSS Base", "Plugin Output"]
    widths = [15, 30, 30, 8, 8, 12, 40, 50, 50, 20, 10, 80]
    
    for sev_level, sev_name in sev_map.items():
        ws = wb.create_sheet(sev_name)
        set_headers_and_widths(ws, headers, widths)
        row = 2
        for host in hosts_data:
            for vuln in host['vulnerabilities']:
                if vuln['severity'] == sev_level:
                    data = [
                        host['ip'], host['fqdn'], host['os'], vuln['port'], vuln['protocol'],
                        vuln['plugin_id'], vuln['plugin_name'], vuln['synopsis'], vuln['solution'],
                        vuln['cve'], vuln['cvss_base_score'], vuln['plugin_output']
                    ]
                    for col, value in enumerate(data, 1):
                        cell = ws.cell(row=row, column=col, value=str(value))
                        apply_style(cell, STYLES.get(f'sev_{sev_level}', STYLES['cell']))
                    row += 1

def create_host_summary_sheet(wb, hosts_data):
    ws = wb.create_sheet("Host Summary")
    headers = ["Host IP", "FQDN", "OS", "Critical", "High", "Medium", "Low", "Info", "Total Vulns", "Open Ports"]
    widths = [15, 30, 40, 10, 10, 10, 10, 10, 12, 12]
    set_headers_and_widths(ws, headers, widths)
    
    row = 2
    for host in hosts_data:
        vuln_counts = {4:0, 3:0, 2:0, 1:0, 0:0}
        for vuln in host['vulnerabilities']:
            vuln_counts[vuln['severity']] += 1
        
        total_vulns = sum(vuln_counts.values())
        
        data = [
            host['ip'], host['fqdn'], host['os'],
            vuln_counts[4], vuln_counts[3], vuln_counts[2], vuln_counts[1], vuln_counts[0],
            total_vulns, len(host['ports'])
        ]
        for col, value in enumerate(data, 1):
            cell = ws.cell(row=row, column=col, value=value)
            apply_style(cell, STYLES['cell_center'])
        row += 1

def create_port_summary_sheet(wb, hosts_data):
    ws = wb.create_sheet("Port Summary")
    headers = ["Host IP", "FQDN", "Port", "Protocol", "Service Name"]
    widths = [15, 30, 10, 10, 25]
    set_headers_and_widths(ws, headers, widths)
    
    all_ports = []
    for host in hosts_data:
        for port, proto, svc in host['ports']:
            all_ports.append((host['ip'], host['fqdn'], int(port), proto, svc))
            
    # Sort by IP, then Port
    all_ports.sort(key=lambda x: (x[0], x[2]))

    row = 2
    for ip, fqdn, port, proto, svc in all_ports:
        data = [ip, fqdn, port, proto, svc]
        for col, value in enumerate(data, 1):
            cell = ws.cell(row=row, column=col, value=value)
            apply_style(cell, STYLES['cell'])
        row += 1

def create_compliance_sheets(wb, hosts_data):
    # Aggregate all compliance data
    all_checks = []
    policy_files = set()
    for host in hosts_data:
        for check in host['compliance_checks']:
            all_checks.append(check)
            if check['audit_file'] != 'N/A':
                policy_files.add(check['audit_file'])
    
    if not all_checks:
        return

    # Create one sheet per policy file
    for policy in sorted(list(policy_files)):
        sheet_name = "".join(c for c in policy if c.isalnum() or c in (' ', '_')).rstrip()[:25]
        ws = wb.create_sheet(f"COMPLIANCE {sheet_name}")
        headers = ["Host IP", "Result", "Check Name", "Policy Value", "Actual Value", "Info", "Solution"]
        widths = [15, 10, 50, 30, 30, 50, 50]
        set_headers_and_widths(ws, headers, widths)
        row = 2
        for check in all_checks:
            if check['audit_file'] == policy:
                data = [
                    check['host_ip'], check['result'], check['check_name'], check['policy_value'],
                    check['actual_value'], check['info'], check['solution']
                ]
                for col, value in enumerate(data, 1):
                    cell = ws.cell(row=row, column=col, value=value)
                    apply_style(cell, STYLES['cell'])
                row += 1

def create_comparison_sheets(wb, previous_file, current_file):
    """Creates sheets for new and closed vulnerabilities."""
    print(f"Comparing {previous_file} and {current_file}...")
    
    try:
        previous_tree = etree.parse(previous_file)
        current_tree = etree.parse(current_file)
    except Exception as e:
        print(f"Error parsing comparison files: {e}")
        return

    previous_hosts = previous_tree.findall('.//ReportHost')
    current_hosts = current_tree.findall('.//ReportHost')

    previous_vulns = extract_vulnerabilities_for_compare(previous_hosts)
    current_vulns = extract_vulnerabilities_for_compare(current_hosts)

    closed_out = [v for k, v in previous_vulns.items() if k not in current_vulns]
    new_vulns = [v for k, v in current_vulns.items() if k not in previous_vulns]

    # Sort by severity (desc) then host IP
    closed_out.sort(key=lambda x: (-x['severity'], x['host_ip']))
    new_vulns.sort(key=lambda x: (-x['severity'], x['host_ip']))
    
    # --- New Vulns Sheet ---
    ws_new = wb.active
    ws_new.title = "New Vulnerabilities"
    headers = ["Host IP", "Severity", "Plugin Name", "Plugin ID", "Port", "Protocol"]
    widths = [15, 10, 50, 12, 8, 8]
    set_headers_and_widths(ws_new, headers, widths)
    row = 2
    for vuln in new_vulns:
        sev_map = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}
        data = [vuln['host_ip'], sev_map.get(vuln['severity'], 'Info'), vuln['plugin_name'], vuln['plugin_id'], vuln['port'], vuln['protocol']]
        for col, value in enumerate(data, 1):
            cell = ws_new.cell(row=row, column=col, value=value)
            apply_style(cell, STYLES.get(f'sev_{vuln["severity"]}', STYLES['cell']))
        row += 1
    
    # --- Closed Vulns Sheet ---
    ws_closed = wb.create_sheet("Closed Vulnerabilities")
    set_headers_and_widths(ws_closed, headers, widths)
    row = 2
    for vuln in closed_out:
        sev_map = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}
        data = [vuln['host_ip'], sev_map.get(vuln['severity'], 'Info'), vuln['plugin_name'], vuln['plugin_id'], vuln['port'], vuln['protocol']]
        for col, value in enumerate(data, 1):
            cell = ws_closed.cell(row=row, column=col, value=value)
            apply_style(cell, STYLES['cell'])
        row += 1

    print(f"Comparison complete: Found {len(new_vulns)} new and {len(closed_out)} closed vulnerabilities.")

# --- Main Execution ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Parse Nessus XMLv2 files into a detailed Excel report.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-f', '--file', help='Single Nessus XMLv2 scan file to parse.')
    parser.add_argument('-d', '--directory', help='Directory containing Nessus XMLv2 scan files.')
    parser.add_argument('-p', '--previous', help='Previous Nessus scan file for comparison mode.')
    parser.add_argument('-c', '--current', help='Current Nessus scan file for comparison mode.')
    parser.add_argument('-o', '--output', default='nessus_report', help='Output prefix name for report (default: nessus_report).')
    parser.add_argument('-r', '--recast', help='''Path to a CSV file for recasting severities.
Format: pluginID,old_severity,new_severity
Example: 51192,2,4''')
    
    args = parser.parse_args()

    # --- Argument Validation ---
    is_report_mode = args.file or args.directory
    is_compare_mode = args.previous and args.current

    if not is_report_mode and not is_compare_mode:
        parser.print_help()
        exit()
    if is_report_mode and is_compare_mode:
        print("Error: Cannot run in standard report mode (-f/-d) and comparison mode (-p/-c) simultaneously.")
        exit()
    if args.file and args.directory:
        print("Error: Please specify a single file (-f) or a directory (-d), not both.")
        exit()

    # --- File Setup ---
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = f"{args.output}_{timestamp}.xlsx"
    
    if args.recast:
        parse_recast_file(args.recast)

    wb = openpyxl.Workbook()
    wb.remove(wb.active) # Remove default sheet
    STYLES = create_styles()

    # --- Mode Execution ---
    if is_compare_mode:
        create_comparison_sheets(wb, args.previous, args.current)
    
    elif is_report_mode:
        xml_files = []
        if args.file:
            if os.path.exists(args.file):
                xml_files.append(args.file)
            else:
                print(f"Error: File not found at {args.file}")
                exit(1)
        elif args.directory:
            if os.path.isdir(args.directory):
                xml_files.extend([os.path.join(args.directory, f) for f in os.listdir(args.directory) if f.lower().endswith(('.nessus', '.xml'))])
            else:
                print(f"Error: Directory not found at {args.directory}")
                exit(1)

        if not xml_files:
            print("No .nessus or .xml files found.")
            exit()
            
        print(f"Found {len(xml_files)} file(s) to parse...")
        for file in xml_files:
            try:
                print(f"  Parsing {os.path.basename(file)}...")
                tree = etree.parse(file)
                report_hosts = tree.findall('.//ReportHost')
                for host_root in report_hosts:
                    normalize_and_extract_data(host_root, os.path.basename(file))
            except etree.XMLSyntaxError:
                print(f"  Warning: Could not parse {file}. It may not be a valid XML file.")
            except Exception as e:
                print(f"  An unexpected error occurred with {file}: {e}")
        
        print("Parsing complete. Generating Excel report...")

        # Calculate summaries before creating sheets
        summary_counts = {'by_severity': {4:0, 3:0, 2:0, 1:0, 0:0}}
        for host in hosts_data:
            for vuln in host['vulnerabilities']:
                summary_counts['by_severity'][vuln['severity']] += 1
                
        # Create worksheets
        wb.create_sheet("Home", 0) # Create Home sheet first
        create_home_sheet(wb, summary_counts)
        create_vulnerability_sheets(wb, hosts_data)
        create_host_summary_sheet(wb, hosts_data)
        create_port_summary_sheet(wb, hosts_data)
        create_compliance_sheets(wb, hosts_data)
        # Add other sheet creation functions here as they are developed
        
    # --- Save Workbook ---
    try:
        wb.save(report_file)
        print(f"\nSuccessfully created report: {report_file}")
    except Exception as e:
        print(f"\nError saving Excel file: {e}")
