# NPM Malicious Package Scanner 🛡️

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/wuwangzhang1216/npm-malicious-scanner)
[![Node](https://img.shields.io/badge/node-%3E%3D14.0.0-brightgreen.svg)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-enterprise--grade-orange.svg)](https://github.com/wuwangzhang1216/npm-malicious-scanner)

## 🎯 Overview

Enterprise-grade security scanner specifically designed to detect and prevent NPM supply chain attacks, with special focus on the September 8, 2025 attack patterns. This tool provides comprehensive protection against malicious packages, typosquatting, and sophisticated supply chain threats.

## ⚡ Key Features

### 🔍 Advanced Detection Capabilities

- **Known Malicious Packages**: Database of confirmed malicious packages from the September 2025 attacks
- **Behavioral Analysis**: Detects suspicious code patterns and behaviors
- **Obfuscation Detection**: Identifies deliberately obscured malicious code
- **Network Monitoring**: Flags suspicious network connections and C&C communications
- **Credential Harvesting Detection**: Identifies attempts to steal tokens and secrets
- **Cryptojacking Detection**: Finds cryptocurrency mining and wallet hijacking code

### 🛡️ Protection Mechanisms

- **Real-time Scanning**: Continuous monitoring of package installations
- **Integrity Verification**: Validates package authenticity and checksums
- **Typosquatting Detection**: Identifies packages with names similar to popular libraries
- **Lock File Analysis**: Verifies package-lock.json integrity
- **Environment Variable Protection**: Detects attempts to access sensitive env vars

### 📊 Reporting & Analytics

- **Security Score**: 0-100 scoring system for overall project security
- **Threat Severity Levels**: Critical, High, Medium, Low classifications
- **JSON & HTML Reports**: Detailed reports in multiple formats
- **Actionable Remediation**: Specific steps to fix identified issues
- **Audit Integration**: Works with npm audit for comprehensive coverage

## 🚀 Quick Start

### Installation

```bash
# Global installation (recommended)
npm install -g npm-malicious-scanner

# Or clone and run directly
git clone https://github.com/wuwangzhang1216/npm-malicious-scanner.git
cd npm-malicious-scanner
npm install
```

### Basic Usage

```bash
# Scan current directory
npm-scanner

# Scan specific project
npm-scanner /path/to/project

# Scan with verbose output
DEBUG=* npm-scanner

# Get help
npm-scanner --help
```

## 📖 Detailed Usage Guide

### Command Line Options

```bash
npm-scanner [options] [target-directory]

Options:
  --help, -h          Show help information
  --version           Show version number
  --verbose           Enable verbose output
  --json              Output results in JSON format
  --html              Generate HTML report
  --fix               Attempt to auto-fix issues (experimental)
  --ignore-dev        Skip devDependencies
  --depth <number>    Max scan depth (default: 5)
```

### Example Commands

```bash
# Basic scan of current project
npm-scanner .

# Scan and generate HTML report
npm-scanner --html /my/project

# Scan with JSON output for CI/CD
npm-scanner --json > security-report.json

# Verbose scan for debugging
npm-scanner --verbose /suspicious/project
```

## 🎨 Understanding the Output

### Security Score Interpretation

- 🟢 **90-100**: Excellent - No significant threats detected
- 🟡 **70-89**: Good - Minor issues that should be addressed
- 🟠 **50-69**: Warning - Several security concerns requiring attention
- 🔴 **0-49**: Critical - Immediate action required

### Threat Severity Levels

1. **CRITICAL** 🚨
   - Known malicious packages
   - Active exploitation detected
   - Credential theft attempts
   - Immediate removal required

2. **HIGH** ⚠️
   - Suspicious network connections
   - Obfuscated code with malicious patterns
   - Typosquatting attempts
   - Should be addressed urgently

3. **MEDIUM** ⚡
   - Outdated packages with vulnerabilities
   - Suspicious scripts in package.json
   - Unusual binary files
   - Plan for remediation

4. **LOW** 📝
   - Best practice violations
   - Missing lock files
   - Configuration issues
   - Address when convenient

## 🔧 Detection Patterns

### September 2025 Attack Signatures

The scanner specifically looks for patterns from the September 8, 2025 supply chain attack:

```javascript
// Malicious packages from the attack
const compromisedPackages = [
  'chalk@5.6.1',
  'debug@4.4.2',
  'ansi-styles@6.2.2',
  'strip-ansi@7.1.1',
  'minimist@1.2.9'
];

// C&C domains used in the attack
const maliciousDomains = [
  'websocket-api2.publicvm.com',
  'static-mw-host.b-cdn.net',
  'img-data-backup.b-cdn.net',
  'npmjs.help'
];

// Worm propagation patterns
const wormSignatures = [
  'Shai-Hulud',
  's1ngularity-repository',
  'telemetry.js'
];
```

### Common Attack Vectors Detected

1. **Cryptocurrency Wallet Hijacking**
   - MetaMask injection
   - Ethereum address replacement
   - Private key extraction

2. **Credential Harvesting**
   - NPM token theft
   - GitHub token extraction
   - AWS/Azure credential access

3. **Supply Chain Propagation**
   - Self-replicating code
   - Automatic infection of dependencies
   - Registry poisoning attempts

4. **Data Exfiltration**
   - WebSocket connections to C&C servers
   - Base64 encoded payloads
   - DNS tunneling attempts

## 🛠️ Integration

### CI/CD Pipeline Integration

#### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  npm-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '16'

      - name: Install dependencies
        run: npm ci

      - name: Run security scanner
        run: |
          npm install -g npm-malicious-scanner
          npm-scanner --json > security-report.json

      - name: Upload report
        uses: actions/upload-artifact@v2
        with:
          name: security-report
          path: security-report.json

      - name: Fail if critical threats
        run: |
          if grep -q '"severity":"CRITICAL"' security-report.json; then
            echo "Critical security threats detected!"
            exit 1
          fi
```

#### GitLab CI

```yaml
security_scan:
  stage: test
  script:
    - npm install -g npm-malicious-scanner
    - npm-scanner --json > security-report.json
  artifacts:
    reports:
      security: security-report.json
  only:
    - merge_requests
    - master
```

#### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh 'npm install -g npm-malicious-scanner'
                sh 'npm-scanner --json > security-report.json'

                publishHTML([
                    reportDir: '.',
                    reportFiles: 'npm-security-report.html',
                    reportName: 'NPM Security Report'
                ])
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'security-report.json'
        }
    }
}
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit

# Run security scan before committing
npx npm-malicious-scanner --json > /tmp/security-check.json

# Check for critical threats
if grep -q '"severity":"CRITICAL"' /tmp/security-check.json; then
    echo "❌ Critical security threats detected! Commit blocked."
    echo "Run 'npm-scanner' for details."
    exit 1
fi

echo "✅ Security scan passed"
exit 0
```

## 🔐 Security Best Practices

### Immediate Actions (Based on Sept 2025 Attack)

1. **Audit All Dependencies**
   ```bash
   npm-scanner .
   npm audit fix --force
   ```

2. **Rotate Credentials**
   - Revoke all NPM tokens
   - Generate new GitHub personal access tokens
   - Update CI/CD secrets

3. **Lock Dependencies**
   ```bash
   npm install --package-lock-only
   git add package-lock.json
   git commit -m "Lock dependencies"
   ```

4. **Enable 2FA**
   - NPM account: `npm profile enable-2fa auth-and-writes`
   - GitHub account: Settings → Security → Two-factor authentication

### Ongoing Protection

1. **Use npm ci in Production**
   ```bash
   # Instead of npm install
   npm ci --only=production
   ```

2. **Regular Scanning**
   ```bash
   # Add to package.json scripts
   "scripts": {
     "security": "npm-scanner",
     "preinstall": "npm-scanner"
   }
   ```

3. **Dependency Review Process**
   - Review all new dependencies
   - Check package age and download stats
   - Verify publisher identity
   - Inspect source code for suspicious patterns

4. **Private Registry**
   ```bash
   # Use a private registry mirror
   npm config set registry https://your-private-registry.com
   ```

## 📊 Report Formats

### JSON Report Structure

```json
{
  "timestamp": "2025-09-08T10:30:00.000Z",
  "totalPackages": 256,
  "scannedPackages": 256,
  "securityScore": 85,
  "threats": [
    {
      "severity": "CRITICAL",
      "package": "malicious-package",
      "version": "1.0.0",
      "type": "KNOWN_MALICIOUS",
      "message": "Known malicious package from Sept 2025 attack",
      "remediation": "npm uninstall malicious-package",
      "cve": "CVE-2025-SEPT8"
    }
  ],
  "warnings": [],
  "recommendations": []
}
```

### HTML Report

The HTML report provides:
- Visual security score with color coding
- Sortable threat table
- Filterable warnings
- Interactive dependency graph
- Remediation checklist

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/wuwangzhang1216/npm-malicious-scanner.git
cd npm-malicious-scanner

# Install dependencies
npm install

# Run tests
npm test

# Run linter
npm run lint
```

### Adding New Threat Patterns

Edit `npm-scanner.js` and add patterns to the appropriate array:

```javascript
// Add to knownMaliciousPackages
this.knownMaliciousPackages['new-malicious-pkg'] = ['1.0.0', '1.0.1'];

// Add to maliciousPatterns
this.maliciousPatterns.push(/new_malicious_pattern/gi);

// Add to c2Domains
this.c2Domains.push('new-c2-domain.com');
```

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- NPM Security Team
- Security researchers who identified the Sept 2025 attack
- Open source community for continuous improvements

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/wuwangzhang1216/npm-malicious-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/wuwangzhang1216/npm-malicious-scanner/discussions)
- **Security**: Report vulnerabilities to security@example.com

## 🔄 Changelog

### Version 2.0.0 (2025-09-08)
- Initial release with Sept 2025 attack detection
- Advanced obfuscation detection
- HTML report generation
- Typosquatting detection
- Environment variable protection

### Roadmap
- [ ] Machine learning-based anomaly detection
- [ ] Real-time monitoring daemon
- [ ] Integration with corporate SIEM systems
- [ ] Blockchain-based package verification
- [ ] Advanced behavioral analysis

---

**Stay Secure!** 🛡️ Remember: Security is not a one-time check but a continuous process.