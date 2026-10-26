#  RepoShield

### npm Package Risk Scanner

RepoShield is a web-based security analysis tool designed to help developers identify potential risks in npm packages through known vulnerability lookups and static security checks.

##  Features

- **Package Metadata:** Retrieves package information from the npm registry.
- **Vulnerability Detection:** Queries the Open Source Vulnerabilities (OSV) database for known security advisories.
- **Static Security Analysis:** Identifies potentially suspicious lifecycle scripts and command patterns.
- **Dependency Reference Checks:** Flags Git-based and URL-based dependencies for further review.
- **Severity Assessment:** Parses available CVSS information to help prioritize vulnerability findings.
- **Evidence-Based Reports:** Presents findings, supporting evidence, recommendations, and check statuses.
- **Partial Results:** Preserves available results when an upstream security check fails.
- **Interactive Dashboard:** Provides a web interface for submitting packages and reviewing scan reports.

##  Technology Stack

| Component | Technologies |
|---|---|
| Backend | Python, FastAPI |
| HTTP Requests | HTTPX |
| Vulnerability Intelligence | OSV API |
| Package Metadata | npm Registry API |
| Severity Parsing | CVSS |
| Testing | Pytest |
| Frontend | React, JavaScript, CSS |
| Development Server | Vite |

## How It Works

1. The user enters an npm package name and optionally specifies a version.
2. RepoShield retrieves package metadata from the npm registry.
3. Static rules inspect available package manifest information for potentially suspicious patterns.
4. The scanner queries OSV for known vulnerabilities associated with the package version.
5. The results are combined into a report with findings, severity information, and check statuses.
6. The dashboard displays the results and relevant limitations.

## Installation and Setup

### Prerequisites

Install Python, Node.js, npm, and Git.

### 1. Clone the Repository

```bash
git clone <https://github.com/srishtisaini4444/RepoShield.git>
cd reposhield
```

Replace the placeholder with your actual GitHub repository URL.

### 2. Set Up the Backend

Open a terminal in the project directory:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start the backend server:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Backend API documentation:

`http://127.0.0.1:8000/docs`

### 3. Set Up the Frontend

Open a second terminal from the project root:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL displayed by Vite, usually:

`http://127.0.0.1:5173/`

Keep both development servers running while using the application.

##  Running Tests

From the `backend` directory, activate the virtual environment and run:

```powershell
python -m pytest -q
```

## Security Considerations

RepoShield performs metadata-based analysis, vulnerability lookups, and static checks. It does not execute scanned package scripts or run scanned packages.

- A suspicious pattern is an indicator for investigation, not proof of malicious behavior.
- A known vulnerability does not automatically mean that every application using the package is exploitable.
- An empty findings list does not guarantee that a package is secure.
- Results depend on the available package metadata and vulnerability advisory data.

## Current Limitations

- External registry and vulnerability database availability can affect scan completeness.
- Static rules cannot detect every malicious or vulnerable package.
- Advisory severity and affected-version information may require further verification.
- Full dependency lockfile analysis is not currently implemented.
- Transitive dependency risks may not be comprehensively assessed.

## Project Objective

RepoShield demonstrates how package metadata, vulnerability intelligence, and static security analysis can be combined into an accessible tool for assessing npm package risks.

**Project status:** Level 1 prototype.