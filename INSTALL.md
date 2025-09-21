# 🚀 NPM Scanner CLI Installation Guide

## 📋 Prerequisites

- **Node.js** >= 14.0.0
- **NPM** >= 6.0.0

## 🔧 Installation Methods

### Method 1: Global Installation (Recommended)

#### Windows

```powershell
# Run PowerShell as Administrator
cd path\to\Bug-Scanner
.\install.bat

# Or manually:
npm install
npm link
```

#### Linux/macOS

```bash
# Clone or download the repository
cd path/to/Bug-Scanner
chmod +x install.sh
./install.sh

# Or manually:
npm install
sudo npm link
```

### Method 2: NPM Global Install

```bash
# From the project directory
npm install -g .

# Or from npm registry (when published)
npm install -g npm-malicious-scanner
```

### Method 3: Direct Usage (No Installation)

```bash
# From the project directory
npm install
node cli.js [command]
```

## ✅ Verify Installation

```bash
# Check if commands are available
npm-scanner --version
nscan --version

# Test interactive mode
nscan -i
```

## 🎯 Available Commands

After installation, you can use these commands from anywhere:

| Command | Alias | Description |
|---------|-------|-------------|
| `npm-scanner` | `nscan` | Main command |
| `npm-scanner -i` | `nscan -i` | Interactive mode |
| `npm-scanner scan .` | `nscan scan .` | Scan current directory |
| `npm-scanner quick` | `nscan quick` | Quick scan |
| `npm-scanner check <pkg>` | `nscan check <pkg>` | Check specific package |
| `npm-scanner audit` | `nscan audit` | Full security audit |
| `npm-scanner stats` | `nscan stats` | View statistics |
| `npm-scanner monitor` | `nscan monitor` | Real-time monitoring |

## 🎨 Usage Examples

### Interactive Mode (Easiest)
```bash
nscan
# Follow the interactive menu
```

### Quick Scan Current Project
```bash
cd /your/project
nscan quick
```

### Deep Security Scan
```bash
nscan scan . --depth 5 --output table
```

### Check Specific Package
```bash
nscan check express --version 4.18.0
```

### Generate HTML Report
```bash
nscan scan . --output html --open
```

### Continuous Monitoring
```bash
nscan monitor --port 3000
```

## 🔧 Configuration

### Set Default Options
```bash
nscan config
```

### Update Threat Database
```bash
nscan update-db
```

## 🐛 Troubleshooting

### Command Not Found

**Windows:**
```powershell
# Add to PATH manually
npm config get prefix
# Add the result\bin to your PATH environment variable
```

**Linux/macOS:**
```bash
# Add to .bashrc or .zshrc
echo 'export PATH="$(npm config get prefix)/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Permission Denied

**Windows:**
- Run PowerShell as Administrator
- Or use: `npm install -g . --force`

**Linux/macOS:**
```bash
sudo npm link
# Or change npm prefix to user directory
npm config set prefix ~/.npm-global
export PATH=~/.npm-global/bin:$PATH
```

### Dependencies Issues
```bash
# Clear npm cache
npm cache clean --force

# Reinstall
rm -rf node_modules package-lock.json
npm install
```

## 🔄 Updating

```bash
# Pull latest changes
git pull

# Reinstall
npm install
npm link
```

## 🗑️ Uninstallation

```bash
# Remove global link
npm unlink -g npm-malicious-scanner

# Or
npm uninstall -g npm-malicious-scanner
```

## 💡 Tips

1. **First Time Users**: Start with interactive mode (`nscan -i`)
2. **CI/CD Integration**: Use `nscan scan . --output json --strict`
3. **Regular Scans**: Add to package.json scripts:
   ```json
   {
     "scripts": {
       "security": "nscan scan .",
       "security:fix": "nscan audit --fix"
     }
   }
   ```

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/wuwangzhang1216/npm-malicious-scanner/issues)
- **Documentation**: [README.md](README.md)

---

**Quick Start After Installation:**
```bash
nscan -i  # Start interactive mode
```