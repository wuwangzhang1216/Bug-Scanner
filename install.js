#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

console.log('🚀 NPM Scanner Global Installation Script\n');
console.log('====================================\n');

/**
 * Global installer for NPM Scanner CLI
 */
class Installer {
    constructor() {
        this.platform = os.platform();
        this.isWindows = this.platform === 'win32';
        this.npmPrefix = this.getNpmPrefix();
    }

    /**
     * Get NPM global prefix
     */
    getNpmPrefix() {
        try {
            return execSync('npm config get prefix', { encoding: 'utf8' }).trim();
        } catch (error) {
            console.error('❌ Error getting npm prefix:', error.message);
            process.exit(1);
        }
    }

    /**
     * Check if running with admin/sudo
     */
    checkPermissions() {
        if (this.isWindows) {
            try {
                execSync('net session', { stdio: 'ignore' });
                return true;
            } catch {
                return false;
            }
        } else {
            return process.getuid() === 0;
        }
    }

    /**
     * Install dependencies
     */
    installDependencies() {
        console.log('📦 Installing dependencies...\n');

        try {
            execSync('npm install', {
                stdio: 'inherit',
                cwd: __dirname
            });
            console.log('\n✅ Dependencies installed successfully');
        } catch (error) {
            console.error('❌ Failed to install dependencies:', error.message);
            process.exit(1);
        }
    }

    /**
     * Create global symlink
     */
    createGlobalLink() {
        console.log('\n🔗 Creating global command link...\n');

        try {
            execSync('npm link', {
                stdio: 'inherit',
                cwd: __dirname
            });
            console.log('\n✅ Global command linked successfully');
        } catch (error) {
            console.error('❌ Failed to create global link:', error.message);
            console.log('\n💡 Try running with administrator privileges:');

            if (this.isWindows) {
                console.log('   Run PowerShell as Administrator and execute:');
                console.log('   npm install -g .');
            } else {
                console.log('   sudo npm install -g .');
            }
            process.exit(1);
        }
    }

    /**
     * Verify installation
     */
    verifyInstallation() {
        console.log('\n🔍 Verifying installation...\n');

        try {
            const version = execSync('npm-scanner --version', { encoding: 'utf8' }).trim();
            console.log(`✅ NPM Scanner v${version} installed successfully!`);
            return true;
        } catch (error) {
            console.error('⚠️  Installation verification failed');
            return false;
        }
    }

    /**
     * Display usage instructions
     */
    showUsageInstructions() {
        console.log('\n' + '='.repeat(60));
        console.log('\n🎉 Installation Complete!\n');
        console.log('You can now use the following commands from anywhere:\n');
        console.log('  • npm-scanner          - Full command');
        console.log('  • nscan                - Short alias');
        console.log('  • npm-scanner -i       - Interactive mode');
        console.log('  • npm-scanner scan .   - Scan current directory');
        console.log('  • npm-scanner --help   - Show all commands\n');
        console.log('Quick start:');
        console.log('  1. cd to your project directory');
        console.log('  2. Run: nscan');
        console.log('  3. Choose "Scan current directory" from the menu\n');
        console.log('='.repeat(60));
    }

    /**
     * Run installation
     */
    async run() {
        console.log(`Platform: ${this.platform}`);
        console.log(`NPM Prefix: ${this.npmPrefix}\n`);

        // Check permissions
        if (!this.checkPermissions()) {
            console.log('⚠️  Warning: Not running with administrator privileges.');
            console.log('   Installation may require elevated permissions.\n');
        }

        // Install dependencies
        this.installDependencies();

        // Create global link
        this.createGlobalLink();

        // Verify installation
        if (this.verifyInstallation()) {
            this.showUsageInstructions();
        } else {
            console.log('\n⚠️  Installation completed but verification failed.');
            console.log('   Try opening a new terminal and running: npm-scanner --version');
        }
    }
}

// Run installer
if (require.main === module) {
    const installer = new Installer();
    installer.run().catch(error => {
        console.error('💥 Installation failed:', error.message);
        process.exit(1);
    });
}

module.exports = Installer;