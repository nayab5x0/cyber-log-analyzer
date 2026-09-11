# Cybersecurity Log Analyzer

## Introduction

Cybersecurity Log Analyzer is a Python-based project that analyzes system login logs and detects suspicious activities.

The system reads log files, extracts important information, cleans the data, analyzes IP addresses and failed login attempts, and generates security reports.

## Features

- Automatically finds `.log` files
- Parses log files using Regular Expressions
- Extracts timestamp, IP address, username, event and status
- Removes duplicate records
- Removes records with missing values
- Validates IP addresses
- Standardizes timestamps
- Normalizes usernames and event information
- Detects suspicious login activities
- Detects high-risk login activities
- Detects possible brute-force activity
- Analyzes suspicious IP addresses
- Counts failed logins by IP and username
- Generates TXT security reports
- Generates Excel security reports

## Threat Detection Rules

The system uses the following rules:

| Condition | Threat Level |
|---|---|
| Less than 5 failed logins | Normal |
| 5 or more failed logins | Suspicious |
| 10 or more failed logins | High Risk |
| 20 or more failed logins | Possible Brute Force |
| 10 or more activities from the same IP | Suspicious IP |

## Project Structure

```text
cyber-log-analyzer/
│
├── data/
│   └── sample_logs.log
│
├── reports/
│   ├── security_report.txt
│   └── security_report.xlsx
│
├── src/
│   ├── log_parser.py
│   ├── detector.py
│   ├── analyzer.py
│   └── report_generator.py
│
├── main.py
├── requirements.txt
├── README.md
└── .gitignore