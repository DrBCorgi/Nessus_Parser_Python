<b>Nessus XML Parser to Excel</b>

This Python script parses Nessus XMLv2 scan files, extracts vulnerability and port information, and generates a detailed Excel report. It can process single or multiple scan files and also includes a feature to compare two scans to identify new and resolved vulnerabilities.

<b>Features</b>
Parses .nessus (XMLv2) files.
Generates a multi-sheet Excel report categorized by vulnerability severity (Critical, High, Medium, Low, Info).
Creates a summary worksheet with a pie chart for vulnerability distribution.
Generates a detailed and a sorted summary of open ports.
Compares two scan files to report on New and Closed Out vulnerabilities.
Customizable output file name.
Getting Started
Prerequisites
Python 3
pip package installer

Installation
Clone the repository and install the required Python libraries using pip:

Bash

pip install lxml openpyxl

Usage
You can run the script from your terminal. Use the -v flag to see the help menu.

Bash

python nessus_Parser_Report.py -v
Arguments
Argument	Long Version	Description
-f	--file	Specify a single .nessus file to parse.
-d	--directory	Specify a directory containing .nessus files to parse.
-o	--output	Set a custom prefix for the output Excel report (default: nessus_report).
-p	--previous	Specify the previous/old scan file for comparison mode.
-c	--current	Specify the current/new scan file for comparison mode.
-v	--version	Display the help message.

Export to Sheets
Examples
1. Parse a Single Nessus File
This will process scan_results.nessus and create a report named nessus_report_[timestamp].xlsx in the same directory.

Bash

python nessus_Parser_Report.py -f /path/to/your/scan_results.nessus
2. Parse All Nessus Files in a Directory
This will process all .nessus files found in the scans directory and generate a single combined report.

Bash

python nessus_Parser_Report.py -d /path/to/scans/
3. Specify a Custom Output File Name
This will process the file and create a report named My_Custom_Report_[timestamp].xlsx.

Bash

python nessus_Parser_Report.py -f scan_results.nessus -o My_Custom_Report
4. Compare Two Scan Files
This will compare old_scan.nessus and new_scan.nessus to generate a report showing the differences, including new and closed-out vulnerabilities.

Bash

python nessus_Parser_Report.py -p /path/to/old_scan.nessus -c /path/to/new_scan.nes
