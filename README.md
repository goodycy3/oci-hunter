# OCI-IAM-AUDIT

<div align="center">

![OCI-IAM-AUDIT Banner](https://img.shields.io/badge/OCI-IAM--AUDIT-orange?style=for-the-badge&logo=oracle)
[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![OCI SDK](https://img.shields.io/badge/OCI%20SDK-2.126.4-red?style=for-the-badge)](https://pypi.org/project/oci/)

**A professional security testing and IAM assessment tool for Oracle Cloud Infrastructure**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Examples](#examples) • [Documentation](#documentation)

</div>

---

## Overview

**OCI-IAM-AUDIT** is a comprehensive enumeration and security assessment tool designed for Oracle Cloud Infrastructure (OCI) environments. It helps security professionals, penetration testers, and cloud administrators identify IAM misconfigurations, enumerate resources, and assess potential privilege escalation vectors.

### Key Capabilities

- **IAM Enumeration** - Users, groups, policies, and compartments
- **Security Assessment** - Identify dangerous permissions and privilege escalation paths
- **Resource Discovery** - Object Storage buckets and compute instances
- **Detailed Reporting** - Export results to JSON for further analysis
- **User-Friendly Output** - Color-coded results with clear severity indicators
- **Fast & Efficient** - Optimized API calls with proper error handling

---

## Features

### Enumeration Capabilities

| Feature | Description |
|---------|-------------|
| **User Identity** | Retrieve current user information, email, status, and creation date |
| **Group Discovery** | List all IAM groups in the tenancy |
| **Group Memberships** | Identify which groups the current user belongs to |
| **Policy Analysis** | Enumerate and analyze IAM policies with dangerous permission detection |
| **Compartment Mapping** | Discover all compartments and their hierarchy |
| **Resource Discovery** | Find accessible Object Storage buckets across compartments |
| **Object Listing** | List objects within specific buckets |
| **File Download** | Download objects from Object Storage |

### Security Analysis

- ✅ **Privilege Escalation Detection** - Identifies high-risk policy statements
- ✅ **Permission Auditing** - Highlights dangerous permissions (`manage`, `all-resources`)
- ✅ **Severity Classification** - Categorizes findings by risk level (HIGH/MEDIUM)
- ✅ **Comprehensive Reporting** - Export complete audit results in JSON format

---

## 📋 Requirements

- Python 3.6 or higher
- OCI Python SDK
- Valid OCI account with configured credentials
- Appropriate IAM permissions for enumeration

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/oci-iam-audit.git
cd oci-iam-audit
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install oci
```

### 3. Configure OCI Credentials

Create an OCI configuration file at `~/.oci/config`:

```ini
[DEFAULT]
user=ocid1.user.oc1..aaaaaaaaxxxxxxxx
fingerprint=xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
tenancy=ocid1.tenancy.oc1..aaaaaaaaxxxxxxxx
region=us-ashburn-1
key_file=~/.oci/oci_api_key.pem
```

### 4. Make Script Executable

```bash
chmod +x oci-enumeration.py
```

---

## 💡 Usage

### Basic Syntax

```bash
python3 oci-enumeration.py [OPTIONS]
```

### Command-Line Options

#### Authentication Options
```bash
-c, --config PATH       OCI config file path (default: ~/.oci/config)
-p, --profile NAME      OCI config profile to use (default: DEFAULT)
```

#### Enumeration Options
```bash
-u, --user              Enumerate current user identity
-g, --groups            Enumerate all groups in tenancy
--user-groups           Enumerate current user's group memberships
--policies              Enumerate IAM policies
-r, --resources         Enumerate accessible resources (buckets, compute, etc)
--compartments          Enumerate compartments
-a, --all               Perform full enumeration (all of the above)
```

#### Analysis Options
```bash
-e, --escalation        Analyze privilege escalation vectors
```

#### Object Storage Options
```bash
-l, --list-bucket BUCKET              List objects in specified bucket
-d, --download BUCKET OBJECT DEST     Download object from bucket
```

#### Output Options
```bash
-o, --output FILE       Export results to JSON file
-v, --verbose           Enable verbose output
--no-banner             Suppress banner
```

---

## 📚 Examples

### Basic Enumeration

#### Check Current User Identity
```bash
python3 oci-enumeration.py --user
```

#### List All Groups
```bash
python3 oci-enumeration.py --groups
```

#### Check User's Group Memberships
```bash
python3 oci-enumeration.py --user-groups
```

#### Enumerate IAM Policies
```bash
python3 oci-enumeration.py --policies
```

### Advanced Usage

#### Full Enumeration with Output
```bash
python3 oci-enumeration.py --all --output full_audit_results.json
```

#### Security Assessment
```bash
python3 oci-enumeration.py --policies --escalation
```

#### Use Specific Profile
```bash
python3 oci-enumeration.py --all --profile junior-dev --output dev_audit.json
```

#### Discover and Access Object Storage
```bash
# Find accessible buckets
python3 oci-enumeration.py --resources

# List objects in a specific bucket
python3 oci-enumeration.py --list-bucket sensitive-data-bucket

# Download a specific object
python3 oci-enumeration.py --download sensitive-data-bucket config.json ./config.json
```

#### Verbose Mode for Debugging
```bash
python3 oci-enumeration.py --all --verbose
```

#### Silent Mode for Automation
```bash
python3 oci-enumeration.py --all --no-banner --output scan_$(date +%Y%m%d).json
```

---

## 🔍 Understanding Output

### Policy Risk Indicators

The tool highlights potentially dangerous permissions:

| Indicator | Meaning |
|-----------|---------|
| ⚠️ **Yellow** | Potentially dangerous permission detected |
| 🔴 **Red** | High-severity privilege escalation risk |
| ✅ **Green** | Success messages |
| ℹ️ **Blue** | Informational messages |

### Severity Levels

- **HIGH** - Critical findings (e.g., `manage all-resources`, full admin access)
- **MEDIUM** - Moderate risk (e.g., user management, secrets access)
- **LOW** - Informational findings

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ██████╗  ██████╗██╗      ██╗ █████╗ ███╗   ███╗         ║
║    ██╔═══██╗██╔════╝██║      ██║██╔══██╗████╗ ████║         ║
║    ██║   ██║██║     ██║█████╗██║███████║██╔████╔██║         ║
║    ██║   ██║██║     ██║╚════╝██║██╔══██║██║╚██╔╝██║         ║
║    ╚██████╔╝╚██████╗██║      ██║██║  ██║██║ ╚═╝ ██║         ║
║     ╚═════╝  ╚═════╝╚═╝      ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝         ║
║       █████╗ ██╗   ██╗██████╗ ██╗████████╗                  ║
║      ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝                  ║
║      ███████║██║   ██║██║  ██║██║   ██║                     ║
║      ██╔══██║██║   ██║██║  ██║██║   ██║                     ║
║      ██║  ██║╚██████╔╝██████╔╝██║   ██║                     ║
║      ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝                     ║
║                                                              ║
║           ⚡ Oracle Cloud IAM Security Scanner ⚡              ║
║                                                              ║
║               Version: 1.0.0  |  License: MIT                ║
║          For Authorized Security Testing Only                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

[+] Successfully authenticated using profile: DEFAULT

======================================================================
                        CURRENT USER IDENTITY
======================================================================

User Information:
  Name:        john.doe@company.com
  OCID:        ocid1.user.oc1..aaaaaaaabcdefg123456
  Description: Developer Account
  Email:       john.doe@company.com
  Status:      ACTIVE
  Created:     2024-01-15 10:30:45.123456+00:00
```

---

## 🛡️ Security Considerations

### ⚠️ Legal and Ethical Usage

**IMPORTANT:** This tool is designed for authorized security testing only.

- ✅ Only use on OCI tenancies you own or have explicit permission to test
- ✅ Obtain written authorization before conducting security assessments
- ✅ Follow responsible disclosure practices
- ✅ Comply with all applicable laws and regulations
- ❌ Unauthorized access to cloud resources may violate laws (CFAA, GDPR, etc.)

### Audit Logging

All API calls made by this tool are logged in the OCI Audit service. Activities will be visible to tenancy administrators.

### Recommended Permissions

The tool requires at minimum:
- `inspect users`
- `inspect groups`
- `inspect policies`
- `inspect compartments`
- `read objectstorage-namespaces`
- `read buckets`
- `read objects`

---

## 🔧 Troubleshooting

### Common Issues

#### Authentication Failed
```bash
# Check if config file exists
ls -la ~/.oci/config

# Verify file permissions
chmod 600 ~/.oci/config
chmod 600 ~/.oci/*.pem
```

#### No Groups Found
```bash
# Try with verbose mode
python3 oci-enumeration.py --groups --verbose

# Try different profile
python3 oci-enumeration.py --groups --profile admin
```

#### Cannot Access Bucket
```bash
# First discover accessible buckets
python3 oci-enumeration.py --resources

# Use exact bucket name from results
python3 oci-enumeration.py --list-bucket exact-bucket-name
```

---

## 📖 Documentation

For detailed documentation, see:
- [Complete Usage Guide](OCI-ENUMERATION-DOCUMENTATION.md)
- [OCI Python SDK Documentation](https://docs.oracle.com/en-us/iaas/tools/python/latest/)
- [OCI IAM Policies](https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/policygetstarted.htm)

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👥 Authors

https://github.com/r007sec and https://github.com/goodycy3


---

## 🙏 Acknowledgments

- Oracle Cloud Infrastructure for their comprehensive Python SDK
- The security research community for best practices and feedback
- All contributors who have helped improve this tool

---

## 📧 Contact

For questions, issues, or suggestions:
- Open an issue on GitHub

---

## ⭐ Star History

If you find this tool useful, please consider giving it a star! ⭐

---

<div align="center">

**Built with ❤️ for the security community**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/oci-iam-audit?style=social)](https://github.com/yourusername/oci-iam-audit/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/yourusername/oci-iam-audit?style=social)](https://github.com/yourusername/oci-iam-audit/network/members)

</div>
