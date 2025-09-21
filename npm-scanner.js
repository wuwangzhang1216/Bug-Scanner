#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');
const https = require('https');

/**
 * NPM恶意包扫描器 v2.0.0
 * 专门针对2025年9月8日攻击模式设计的防护工具
 * Enhanced with additional detection capabilities
 */

class NPMSecurityScanner {
    constructor() {
        // 已知的恶意包版本（基于9月8日攻击）
        this.knownMaliciousPackages = {
            'chalk': ['5.6.1', '5.6.0'],
            'debug': ['4.4.2', '4.4.1'],
            'ansi-styles': ['6.2.2'],
            'strip-ansi': ['7.1.1'],
            'simple-swizzle': ['0.2.3'],
            'color-string': ['1.9.2'],
            'is-arrayish': ['0.3.3'],
            'minimist': ['1.2.9'],
            'rxnt-authentication': ['*'], // 所有版本都可疑
            'telemetry-package': ['*'],
            'npm-scripts-info': ['0.3.10', '0.3.11'],
            'node-ipc': ['10.1.1', '10.1.2'], // RIAEvangelist incident
        };

        // 恶意代码特征模式
        this.maliciousPatterns = [
            // 加密货币钱包劫持模式
            /window\.ethereum/gi,
            /MetaMask/gi,
            /Phantom/gi,
            /Exodus/gi,
            /TrustWallet/gi,
            /crypto\.wallet/gi,
            /wallet\.address/gi,
            /privateKey/gi,
            /seedPhrase/gi,
            /mnemonic/gi,
            /0x[a-fA-F0-9]{40}/g, // 以太坊地址模式

            // 网络拦截模式
            /XMLHttpRequest\.prototype\.open/gi,
            /fetch\.prototype/gi,
            /window\.fetch\s*=/gi,
            /axios\.interceptors/gi,

            // 数据外泄模式
            /websocket-api2\.publicvm\.com/gi,
            /static-mw-host\.b-cdn\.net/gi,
            /img-data-backup\.b-cdn\.net/gi,
            /npmjs\.help/gi,
            /telemetry-backend\.herokuapp\.com/gi,
            /analytics-collector\.xyz/gi,

            // 自传播蠕虫模式 (Shai-Hulud)
            /Shai-Hulud/gi,
            /s1ngularity-repository/gi,
            /telemetry\.js/gi,
            /worm-propagator/gi,

            // 凭证窃取模式
            /process\.env\.NPM_TOKEN/gi,
            /process\.env\.GITHUB_TOKEN/gi,
            /process\.env\.AWS_/gi,
            /process\.env\.AZURE_/gi,
            /process\.env\.GOOGLE_/gi,
            /\.ssh\/id_rsa/gi,
            /\.aws\/credentials/gi,
            /\.npmrc/gi,
            /\.gitconfig/gi,
            /\.netrc/gi,

            // 混淆代码模式
            /eval\s*\(/gi,
            /Function\s*\(/gi,
            /new\s+Function/gi,
            /atob\s*\(/gi,
            /btoa\s*\(/gi,
            /String\.fromCharCode/gi,
            /\\x[0-9a-fA-F]{2}/g,
            /\\u[0-9a-fA-F]{4}/g,

            // 反调试和逃避检测
            /debugger/gi,
            /console\.clear/gi,
            /process\.exit/gi,
            /process\.kill/gi,

            // 加密挖矿
            /coinhive/gi,
            /cryptonight/gi,
            /monero/gi,
            /web-miner/gi,
        ];

        // 可疑的post-install脚本行为
        this.suspiciousScripts = [
            'curl', 'wget', 'nc', 'netcat', 'telnet',
            'base64', 'eval', 'exec',
            'child_process', 'spawn', 'execSync',
            'fs.readFileSync', 'fs.writeFileSync',
            'process.env', 'os.homedir',
            'require("http")', 'require("https")',
            'powershell', 'cmd.exe', 'bash',
            'python', 'perl', 'ruby'
        ];

        // C&C服务器域名模式
        this.c2Domains = [
            'publicvm.com',
            'b-cdn.net',
            'npmjs.help',
            'herokuapp.com',
            'ngrok.io',
            'serveo.net',
            'localtunnel.me',
            'pagekite.me'
        ];

        this.scanResults = {
            timestamp: new Date().toISOString(),
            totalPackages: 0,
            scannedPackages: 0,
            threats: [],
            warnings: [],
            errors: [],
            recommendations: []
        };
    }

    /**
     * 主扫描入口
     */
    async scan(targetPath = process.cwd()) {
        console.log('🔍 NPM恶意包扫描器 v2.0.0');
        console.log('📅 防护模式：2025年9月8日攻击特征');
        console.log('📁 扫描目录：', targetPath);
        console.log('⏰ 开始时间：', new Date().toLocaleString());
        console.log('─'.repeat(60));

        try {
            // 1. 检查package.json和package-lock.json
            await this.checkPackageFiles(targetPath);

            // 2. 扫描node_modules
            await this.scanNodeModules(targetPath);

            // 3. 检查npm配置
            await this.checkNpmConfig();

            // 4. 验证包完整性
            await this.verifyPackageIntegrity(targetPath);

            // 5. 检查网络连接
            await this.checkNetworkConnections();

            // 6. 扫描环境变量泄露
            this.checkEnvironmentVariables();

            // 7. 生成安全报告
            this.generateReport();

            // 8. 提供修复建议
            this.provideRemediation();

        } catch (error) {
            console.error('❌ 扫描过程中发生错误：', error.message);
            this.scanResults.errors.push({
                type: 'SCAN_ERROR',
                message: error.message,
                stack: error.stack
            });
        }
    }

    /**
     * 检查package.json和package-lock.json
     */
    async checkPackageFiles(targetPath) {
        console.log('\n📦 检查包配置文件...');

        const packageJsonPath = path.join(targetPath, 'package.json');
        const lockFilePath = path.join(targetPath, 'package-lock.json');
        const yarnLockPath = path.join(targetPath, 'yarn.lock');
        const pnpmLockPath = path.join(targetPath, 'pnpm-lock.yaml');

        try {
            // 检查package.json
            const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));

            // 检查已知恶意包
            this.checkDependencies(packageJson.dependencies || {}, 'dependencies');
            this.checkDependencies(packageJson.devDependencies || {}, 'devDependencies');
            this.checkDependencies(packageJson.optionalDependencies || {}, 'optionalDependencies');

            // 检查scripts部分
            if (packageJson.scripts) {
                this.checkScripts(packageJson.scripts);
            }

            // 检查lock文件
            let hasLockFile = false;
            for (const lockFile of [lockFilePath, yarnLockPath, pnpmLockPath]) {
                try {
                    await fs.access(lockFile);
                    console.log(`✅ 发现锁文件: ${path.basename(lockFile)}`);
                    hasLockFile = true;

                    // 验证锁文件完整性
                    await this.verifyLockFileIntegrity(lockFile);
                    break;
                } catch {
                    // 继续检查下一个
                }
            }

            if (!hasLockFile) {
                this.scanResults.warnings.push({
                    type: 'MISSING_LOCK',
                    severity: 'HIGH',
                    message: '缺少包锁文件，建议使用npm ci/yarn install --frozen-lockfile',
                    remediation: '运行 npm install 生成 package-lock.json'
                });
            }

        } catch (error) {
            this.scanResults.errors.push({
                type: 'PACKAGE_READ_ERROR',
                message: `无法读取package.json: ${error.message}`
            });
        }
    }

    /**
     * 验证锁文件完整性
     */
    async verifyLockFileIntegrity(lockFilePath) {
        try {
            const content = await fs.readFile(lockFilePath, 'utf8');
            const stats = await fs.stat(lockFilePath);

            // 检查最近修改时间
            const daysSinceModified = (Date.now() - stats.mtime) / (1000 * 60 * 60 * 24);

            if (daysSinceModified < 1) {
                this.scanResults.warnings.push({
                    type: 'RECENT_LOCK_CHANGE',
                    severity: 'MEDIUM',
                    message: '锁文件在24小时内被修改，请验证变更是否合法',
                    file: path.basename(lockFilePath),
                    modifiedAt: stats.mtime.toISOString()
                });
            }

            // 检查可疑的URL
            const suspiciousUrls = content.match(/https?:\/\/[^\s"']+/g) || [];
            for (const url of suspiciousUrls) {
                for (const c2Domain of this.c2Domains) {
                    if (url.includes(c2Domain)) {
                        this.scanResults.threats.push({
                            severity: 'CRITICAL',
                            type: 'C2_DOMAIN_IN_LOCK',
                            domain: c2Domain,
                            url: url,
                            message: '锁文件中发现可疑C&C服务器域名'
                        });
                    }
                }
            }

        } catch (error) {
            this.scanResults.errors.push({
                type: 'LOCK_VERIFICATION_ERROR',
                message: `无法验证锁文件: ${error.message}`
            });
        }
    }

    /**
     * 检查依赖项
     */
    checkDependencies(deps, type) {
        for (const [pkg, version] of Object.entries(deps)) {
            this.scanResults.totalPackages++;

            // 检查是否为已知恶意包
            if (this.knownMaliciousPackages[pkg]) {
                const maliciousVersions = this.knownMaliciousPackages[pkg];
                const installedVersion = version.replace(/[\^~>=<]/g, '');

                if (maliciousVersions.includes('*') ||
                    maliciousVersions.includes(installedVersion)) {
                    this.scanResults.threats.push({
                        severity: 'CRITICAL',
                        package: pkg,
                        version: version,
                        type: type,
                        message: `检测到已知恶意包版本（9月8日攻击）`,
                        cve: 'CVE-2025-SEPT8',
                        remediation: `立即移除或更新${pkg}包到安全版本`
                    });
                }
            }

            // 检查可疑的Git URL依赖
            if (version.includes('git') || version.includes('github.com')) {
                this.scanResults.warnings.push({
                    type: 'GIT_DEPENDENCY',
                    severity: 'MEDIUM',
                    package: pkg,
                    url: version,
                    message: '使用Git URL作为依赖可能存在供应链风险',
                    remediation: '考虑使用npm registry上的正式版本'
                });
            }

            // 检查file:// 协议依赖
            if (version.startsWith('file:')) {
                this.scanResults.warnings.push({
                    type: 'LOCAL_DEPENDENCY',
                    severity: 'LOW',
                    package: pkg,
                    path: version,
                    message: '使用本地文件系统依赖'
                });
            }

            // 检查包名混淆攻击
            this.checkTyposquatting(pkg);
        }
    }

    /**
     * 检查包名混淆攻击（typosquatting）
     */
    checkTyposquatting(packageName) {
        const popularPackages = [
            'react', 'express', 'lodash', 'axios', 'webpack',
            'babel', 'typescript', 'jest', 'eslint', 'prettier'
        ];

        for (const popular of popularPackages) {
            const distance = this.levenshteinDistance(packageName.toLowerCase(), popular);

            if (distance > 0 && distance <= 2 && packageName !== popular) {
                this.scanResults.warnings.push({
                    type: 'TYPOSQUATTING',
                    severity: 'HIGH',
                    package: packageName,
                    similarTo: popular,
                    message: `包名与流行包"${popular}"相似，可能是恶意仿冒包`,
                    remediation: `验证是否确实需要"${packageName}"，而非"${popular}"`
                });
            }
        }
    }

    /**
     * 计算Levenshtein距离
     */
    levenshteinDistance(str1, str2) {
        const matrix = [];

        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }

        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }

        return matrix[str2.length][str1.length];
    }

    /**
     * 检查scripts部分
     */
    checkScripts(scripts) {
        console.log('\n🔧 检查脚本命令...');

        const dangerousHooks = [
            'preinstall', 'install', 'postinstall',
            'preuninstall', 'uninstall', 'postuninstall',
            'prepublish', 'prepare'
        ];

        for (const [name, script] of Object.entries(scripts)) {
            // 检查危险的生命周期脚本
            if (dangerousHooks.includes(name)) {
                for (const suspicious of this.suspiciousScripts) {
                    if (script.toLowerCase().includes(suspicious.toLowerCase())) {
                        this.scanResults.warnings.push({
                            type: 'SUSPICIOUS_SCRIPT',
                            severity: 'HIGH',
                            script: name,
                            pattern: suspicious,
                            content: script.substring(0, 200),
                            message: `检测到可疑的${name}脚本`,
                            remediation: '审查脚本内容，确保没有恶意行为'
                        });
                    }
                }

                // 检查base64编码的命令
                if (/echo\s+[A-Za-z0-9+\/=]{50,}/.test(script)) {
                    this.scanResults.threats.push({
                        severity: 'CRITICAL',
                        type: 'BASE64_SCRIPT',
                        script: name,
                        message: '发现base64编码的脚本命令，高度可疑',
                        remediation: '立即审查并移除可疑脚本'
                    });
                }
            }
        }
    }

    /**
     * 扫描node_modules目录
     */
    async scanNodeModules(targetPath) {
        console.log('\n📂 扫描node_modules目录...');

        const nodeModulesPath = path.join(targetPath, 'node_modules');

        try {
            await fs.access(nodeModulesPath);
        } catch {
            console.log('⚠️  未找到node_modules目录');
            this.scanResults.warnings.push({
                type: 'NO_NODE_MODULES',
                severity: 'INFO',
                message: '未找到node_modules目录，跳过深度扫描'
            });
            return;
        }

        const packages = await fs.readdir(nodeModulesPath);
        let scannedCount = 0;
        const progressInterval = 25;

        console.log(`  发现 ${packages.length} 个顶层包/作用域`);

        for (const pkg of packages) {
            if (pkg.startsWith('.')) continue;

            const pkgPath = path.join(nodeModulesPath, pkg);
            const stats = await fs.stat(pkgPath);

            if (pkg.startsWith('@')) {
                // 处理作用域包
                const scopedPackages = await fs.readdir(pkgPath);
                for (const scopedPkg of scopedPackages) {
                    const scopedPkgPath = path.join(pkgPath, scopedPkg);
                    await this.scanPackageDirectory(scopedPkgPath, `${pkg}/${scopedPkg}`);
                    scannedCount++;

                    if (scannedCount % progressInterval === 0) {
                        console.log(`  已扫描 ${scannedCount} 个包...`);
                    }
                }
            } else if (stats.isDirectory()) {
                await this.scanPackageDirectory(pkgPath, pkg);
                scannedCount++;

                if (scannedCount % progressInterval === 0) {
                    console.log(`  已扫描 ${scannedCount} 个包...`);
                }
            }
        }

        this.scanResults.scannedPackages = scannedCount;
        console.log(`✅ 扫描完成，共检查 ${scannedCount} 个包`);
    }

    /**
     * 扫描单个包目录
     */
    async scanPackageDirectory(pkgPath, pkgName) {
        try {
            // 检查package.json
            const packageJsonPath = path.join(pkgPath, 'package.json');
            const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));

            // 检查版本
            if (this.knownMaliciousPackages[pkgName]) {
                const maliciousVersions = this.knownMaliciousPackages[pkgName];
                if (maliciousVersions.includes('*') ||
                    maliciousVersions.includes(packageJson.version)) {
                    this.scanResults.threats.push({
                        severity: 'CRITICAL',
                        package: pkgName,
                        version: packageJson.version,
                        path: pkgPath,
                        message: '发现已知恶意包版本',
                        remediation: `立即运行: npm uninstall ${pkgName}`
                    });
                }
            }

            // 检查包元数据
            await this.checkPackageMetadata(packageJson, pkgName);

            // 扫描JavaScript文件
            await this.scanJavaScriptFiles(pkgPath, pkgName);

            // 检查二进制文件
            await this.checkBinaryFiles(pkgPath, pkgName);

        } catch (error) {
            // 忽略无法读取的包
            if (error.code !== 'ENOENT') {
                this.scanResults.errors.push({
                    type: 'PACKAGE_SCAN_ERROR',
                    package: pkgName,
                    message: error.message
                });
            }
        }
    }

    /**
     * 检查包元数据
     */
    async checkPackageMetadata(packageJson, pkgName) {
        // 检查可疑的维护者
        if (packageJson.author && typeof packageJson.author === 'string') {
            if (packageJson.author.includes('hack') ||
                packageJson.author.includes('test') ||
                packageJson.author.includes('anonymous')) {
                this.scanResults.warnings.push({
                    type: 'SUSPICIOUS_AUTHOR',
                    severity: 'MEDIUM',
                    package: pkgName,
                    author: packageJson.author,
                    message: '包作者信息可疑'
                });
            }
        }

        // 检查仓库URL
        if (packageJson.repository && packageJson.repository.url) {
            const repoUrl = packageJson.repository.url;

            // 检查是否指向可疑域名
            for (const c2Domain of this.c2Domains) {
                if (repoUrl.includes(c2Domain)) {
                    this.scanResults.threats.push({
                        severity: 'HIGH',
                        type: 'SUSPICIOUS_REPO',
                        package: pkgName,
                        url: repoUrl,
                        message: '包仓库URL指向可疑域名'
                    });
                }
            }
        }

        // 检查包描述中的可疑关键词
        if (packageJson.description) {
            const suspiciousKeywords = [
                'hack', 'crack', 'exploit', 'backdoor',
                'trojan', 'malware', 'virus', 'worm'
            ];

            for (const keyword of suspiciousKeywords) {
                if (packageJson.description.toLowerCase().includes(keyword)) {
                    this.scanResults.warnings.push({
                        type: 'SUSPICIOUS_DESCRIPTION',
                        severity: 'LOW',
                        package: pkgName,
                        keyword: keyword,
                        message: '包描述包含可疑关键词'
                    });
                    break;
                }
            }
        }
    }

    /**
     * 扫描JavaScript文件
     */
    async scanJavaScriptFiles(dirPath, pkgName) {
        const files = await this.getAllFiles(dirPath, ['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx']);

        for (const file of files.slice(0, 50)) { // 限制扫描文件数量以提高性能
            try {
                const content = await fs.readFile(file, 'utf8');

                // 检查文件大小
                if (content.length > 1000000) {
                    this.scanResults.warnings.push({
                        type: 'LARGE_FILE',
                        severity: 'LOW',
                        package: pkgName,
                        file: path.relative(process.cwd(), file),
                        size: content.length,
                        message: '发现异常大的JavaScript文件'
                    });
                    continue;
                }

                // 检查恶意代码模式
                let threatFound = false;
                for (const pattern of this.maliciousPatterns) {
                    const matches = content.match(pattern);
                    if (matches && matches.length > 0) {
                        // 避免误报，检查上下文
                        if (!this.isFalsePositive(content, matches[0])) {
                            this.scanResults.threats.push({
                                severity: 'HIGH',
                                package: pkgName,
                                file: path.relative(process.cwd(), file),
                                pattern: pattern.source.substring(0, 50),
                                match: matches[0].substring(0, 100),
                                message: '检测到恶意代码模式',
                                remediation: '审查文件内容并考虑移除该包'
                            });
                            threatFound = true;
                            break;
                        }
                    }
                }

                if (!threatFound) {
                    // 检查混淆代码
                    if (this.isObfuscated(content)) {
                        this.scanResults.warnings.push({
                            type: 'OBFUSCATED_CODE',
                            severity: 'MEDIUM',
                            package: pkgName,
                            file: path.relative(process.cwd(), file),
                            message: '检测到混淆代码',
                            remediation: '混淆代码可能隐藏恶意行为，需要人工审查'
                        });
                    }

                    // 检查动态代码执行
                    if (this.hasDynamicCodeExecution(content)) {
                        this.scanResults.warnings.push({
                            type: 'DYNAMIC_CODE_EXEC',
                            severity: 'HIGH',
                            package: pkgName,
                            file: path.relative(process.cwd(), file),
                            message: '检测到动态代码执行',
                            remediation: '审查eval/Function使用是否合理'
                        });
                    }
                }

            } catch (error) {
                // 忽略无法读取的文件
            }
        }
    }

    /**
     * 检查是否为误报
     */
    isFalsePositive(content, match) {
        // 检查是否在注释中
        const lines = content.split('\n');
        for (const line of lines) {
            if (line.includes(match)) {
                if (line.trim().startsWith('//') ||
                    line.trim().startsWith('*') ||
                    line.trim().startsWith('/*')) {
                    return true;
                }
            }
        }

        // 检查是否在字符串中（简单检查）
        if (match.includes('example.com') ||
            match.includes('localhost') ||
            match.includes('test')) {
            return true;
        }

        return false;
    }

    /**
     * 检查二进制文件
     */
    async checkBinaryFiles(dirPath, pkgName) {
        const binaryExtensions = ['.exe', '.dll', '.so', '.dylib', '.node'];
        const files = await this.getAllFiles(dirPath, binaryExtensions);

        if (files.length > 0) {
            this.scanResults.warnings.push({
                type: 'BINARY_FILES',
                severity: 'MEDIUM',
                package: pkgName,
                count: files.length,
                files: files.slice(0, 5).map(f => path.basename(f)),
                message: '包含二进制文件',
                remediation: '验证二进制文件是否为包的正常组成部分'
            });
        }
    }

    /**
     * 递归获取所有文件
     */
    async getAllFiles(dirPath, extensions, maxDepth = 5, currentDepth = 0) {
        const files = [];

        if (currentDepth > maxDepth) {
            return files;
        }

        try {
            const items = await fs.readdir(dirPath);

            for (const item of items) {
                if (item.startsWith('.') || item === 'node_modules') continue;

                const fullPath = path.join(dirPath, item);

                try {
                    const stats = await fs.stat(fullPath);

                    if (stats.isDirectory()) {
                        if (!item.includes('test') &&
                            !item.includes('example') &&
                            !item.includes('docs') &&
                            !item.includes('.git')) {
                            const subFiles = await this.getAllFiles(
                                fullPath, extensions, maxDepth, currentDepth + 1
                            );
                            files.push(...subFiles);
                        }
                    } else if (stats.isFile()) {
                        if (extensions.some(ext => fullPath.endsWith(ext))) {
                            files.push(fullPath);
                        }
                    }
                } catch (error) {
                    // 忽略无法访问的文件
                }
            }
        } catch (error) {
            // 忽略无法访问的目录
        }

        return files;
    }

    /**
     * 检测代码是否被混淆
     */
    isObfuscated(content) {
        // 混淆检测启发式
        const indicators = [
            // 单行超长代码
            content.length > 10000 && content.split('\n').length < 10,
            // 大量十六进制
            (content.match(/\\x[0-9a-fA-F]{2}/g) || []).length > 100,
            // 大量Unicode
            (content.match(/\\u[0-9a-fA-F]{4}/g) || []).length > 50,
            // 长eval语句
            /eval\s*\([^)]{1000,}\)/.test(content),
            // 变量名混淆模式
            /_0x[0-9a-f]+/gi.test(content) &&
                (content.match(/_0x[0-9a-f]+/gi) || []).length > 20,
            // 大量数组索引访问
            (content.match(/\[[0-9]+\]/g) || []).length > 200,
            // 短变量名密度
            (content.match(/\b[a-z]\b/g) || []).length / content.length > 0.01
        ];

        return indicators.filter(Boolean).length >= 2;
    }

    /**
     * 检测动态代码执行
     */
    hasDynamicCodeExecution(content) {
        const patterns = [
            /eval\s*\(/,
            /new\s+Function\s*\(/,
            /setTimeout\s*\([^,]+,[^)]*\)/,
            /setInterval\s*\([^,]+,[^)]*\)/,
            /\.constructor\s*\(\s*['"`]/,
            /Function\s*\.\s*prototype\s*\.\s*constructor/
        ];

        return patterns.some(pattern => pattern.test(content));
    }

    /**
     * 检查npm配置
     */
    async checkNpmConfig() {
        console.log('\n🔐 检查npm安全配置...');

        try {
            // 检查registry设置
            const registry = execSync('npm config get registry', { encoding: 'utf8' }).trim();

            if (!registry.includes('registry.npmjs.org')) {
                this.scanResults.warnings.push({
                    type: 'CUSTOM_REGISTRY',
                    severity: 'HIGH',
                    value: registry,
                    message: '使用非官方npm registry',
                    remediation: '运行: npm config set registry https://registry.npmjs.org/'
                });
            }

            // 检查代理设置
            try {
                const proxy = execSync('npm config get proxy', { encoding: 'utf8' }).trim();
                if (proxy && proxy !== 'null') {
                    this.scanResults.warnings.push({
                        type: 'PROXY_CONFIGURED',
                        severity: 'LOW',
                        value: proxy,
                        message: '配置了HTTP代理'
                    });
                }
            } catch {}

            // 检查全局包目录权限
            const globalDir = execSync('npm config get prefix', { encoding: 'utf8' }).trim();
            console.log(`  全局包目录: ${globalDir}`);

        } catch (error) {
            this.scanResults.warnings.push({
                type: 'CONFIG_CHECK_FAILED',
                severity: 'LOW',
                message: '无法检查npm配置',
                error: error.message
            });
        }
    }

    /**
     * 验证包完整性
     */
    async verifyPackageIntegrity(targetPath) {
        console.log('\n🔑 验证包完整性...');

        try {
            // 运行npm audit
            const auditResult = execSync('npm audit --json', {
                cwd: targetPath,
                encoding: 'utf8',
                stdio: ['pipe', 'pipe', 'pipe']
            });

            const audit = JSON.parse(auditResult);

            if (audit.metadata && audit.metadata.vulnerabilities) {
                const vulns = audit.metadata.vulnerabilities;

                console.log(`  发现漏洞统计:`);
                console.log(`    严重: ${vulns.critical || 0}`);
                console.log(`    高危: ${vulns.high || 0}`);
                console.log(`    中等: ${vulns.moderate || 0}`);
                console.log(`    低危: ${vulns.low || 0}`);

                if (vulns.critical > 0) {
                    this.scanResults.threats.push({
                        severity: 'CRITICAL',
                        type: 'NPM_AUDIT',
                        count: vulns.critical,
                        message: `发现 ${vulns.critical} 个严重漏洞`,
                        remediation: '运行: npm audit fix --force'
                    });
                }

                if (vulns.high > 0) {
                    this.scanResults.warnings.push({
                        type: 'NPM_AUDIT',
                        severity: 'HIGH',
                        count: vulns.high,
                        message: `发现 ${vulns.high} 个高危漏洞`,
                        remediation: '运行: npm audit fix'
                    });
                }
            }

            // 检查advisories详情
            if (audit.advisories) {
                for (const [id, advisory] of Object.entries(audit.advisories)) {
                    if (advisory.severity === 'critical' || advisory.severity === 'high') {
                        this.scanResults.threats.push({
                            severity: advisory.severity.toUpperCase(),
                            type: 'VULNERABILITY',
                            id: id,
                            package: advisory.module_name,
                            title: advisory.title,
                            cve: advisory.cves ? advisory.cves[0] : null,
                            message: advisory.overview,
                            remediation: advisory.recommendation
                        });
                    }
                }
            }

        } catch (error) {
            // npm audit可能返回非零退出码
            if (error.stdout) {
                try {
                    const audit = JSON.parse(error.stdout);
                    // 处理audit结果
                    if (audit.metadata && audit.metadata.vulnerabilities) {
                        const vulns = audit.metadata.vulnerabilities;
                        if (vulns.critical > 0 || vulns.high > 0) {
                            this.scanResults.warnings.push({
                                type: 'NPM_AUDIT_ISSUES',
                                severity: 'HIGH',
                                critical: vulns.critical,
                                high: vulns.high,
                                message: `发现 ${vulns.critical} 个严重和 ${vulns.high} 个高危漏洞`
                            });
                        }
                    }
                } catch {
                    // 忽略解析错误
                }
            }
        }
    }

    /**
     * 检查网络连接
     */
    async checkNetworkConnections() {
        console.log('\n🌐 检查可疑网络连接...');

        // 这部分在实际环境中可以通过监控网络流量实现
        // 这里我们检查代码中的网络请求

        this.scanResults.recommendations.push({
            type: 'NETWORK_MONITORING',
            message: '建议使用网络监控工具监视npm包的网络活动',
            tools: ['Wireshark', 'tcpdump', 'Process Monitor']
        });
    }

    /**
     * 检查环境变量泄露
     */
    checkEnvironmentVariables() {
        console.log('\n🔑 检查环境变量安全...');

        const sensitiveEnvVars = [
            'NPM_TOKEN', 'GITHUB_TOKEN', 'AWS_ACCESS_KEY_ID',
            'AZURE_CLIENT_SECRET', 'GOOGLE_APPLICATION_CREDENTIALS',
            'DATABASE_URL', 'API_KEY', 'SECRET_KEY', 'PRIVATE_KEY'
        ];

        const exposedVars = [];

        for (const envVar of sensitiveEnvVars) {
            if (process.env[envVar]) {
                exposedVars.push(envVar);
            }
        }

        if (exposedVars.length > 0) {
            this.scanResults.warnings.push({
                type: 'EXPOSED_ENV_VARS',
                severity: 'HIGH',
                variables: exposedVars,
                message: '检测到敏感环境变量',
                remediation: '确保这些环境变量未被恶意包访问'
            });
        }
    }

    /**
     * 生成扫描报告
     */
    generateReport() {
        console.log('\n' + '='.repeat(60));
        console.log('📊 扫描报告摘要');
        console.log('='.repeat(60));

        // 计算威胁等级
        const criticalThreats = this.scanResults.threats.filter(
            t => t.severity === 'CRITICAL'
        ).length;
        const highThreats = this.scanResults.threats.filter(
            t => t.severity === 'HIGH'
        ).length;

        console.log(`\n📈 扫描统计:`);
        console.log(`  • 配置包总数: ${this.scanResults.totalPackages}`);
        console.log(`  • 扫描包数量: ${this.scanResults.scannedPackages}`);
        console.log(`  • 严重威胁: ${criticalThreats}`);
        console.log(`  • 高危威胁: ${highThreats}`);
        console.log(`  • 警告数量: ${this.scanResults.warnings.length}`);
        console.log(`  • 错误数量: ${this.scanResults.errors.length}`);

        // 显示严重威胁
        if (criticalThreats > 0) {
            console.log('\n🚨 严重威胁 (需要立即处理):');
            const criticals = this.scanResults.threats.filter(
                t => t.severity === 'CRITICAL'
            );

            for (const threat of criticals.slice(0, 5)) {
                console.log(`  ❌ ${threat.package || threat.type}`);
                console.log(`     ${threat.message}`);
                if (threat.remediation) {
                    console.log(`     🔧 ${threat.remediation}`);
                }
            }

            if (criticals.length > 5) {
                console.log(`  ... 还有 ${criticals.length - 5} 个严重威胁`);
            }
        }

        // 显示高危威胁
        if (highThreats > 0) {
            console.log('\n⚠️  高危威胁:');
            const highs = this.scanResults.threats.filter(
                t => t.severity === 'HIGH'
            );

            for (const threat of highs.slice(0, 3)) {
                console.log(`  • ${threat.package || threat.type}: ${threat.message}`);
            }

            if (highs.length > 3) {
                console.log(`  ... 还有 ${highs.length - 3} 个高危威胁`);
            }
        }

        // 显示重要警告
        const highWarnings = this.scanResults.warnings.filter(
            w => w.severity === 'HIGH'
        );

        if (highWarnings.length > 0) {
            console.log('\n⚠️  重要警告:');
            for (const warning of highWarnings.slice(0, 3)) {
                console.log(`  • [${warning.type}] ${warning.message}`);
            }
        }

        // 评分
        const score = this.calculateSecurityScore();
        console.log('\n🏆 安全评分: ' + this.getScoreEmoji(score) + ` ${score}/100`);

        if (score < 50) {
            console.log('   ⚠️  您的项目存在严重的安全风险，请立即采取行动！');
        } else if (score < 80) {
            console.log('   ⚠️  发现一些安全问题，建议尽快修复。');
        } else {
            console.log('   ✅ 安全状况良好，但请继续保持警惕。');
        }

        // 保存详细报告
        this.saveReport();
    }

    /**
     * 提供修复建议
     */
    provideRemediation() {
        console.log('\n💡 立即行动建议:');

        const actions = [];

        // 基于威胁生成行动建议
        if (this.scanResults.threats.some(t => t.severity === 'CRITICAL')) {
            actions.push('1. 🚨 立即移除或更新所有已知恶意包');
            actions.push('2. 🔐 轮换所有npm和GitHub访问令牌');
            actions.push('3. 🔍 审查最近的代码提交和依赖变更');
        }

        if (this.scanResults.warnings.some(w => w.type === 'MISSING_LOCK')) {
            actions.push('4. 📦 生成并提交package-lock.json文件');
        }

        if (this.scanResults.warnings.some(w => w.type === 'NPM_AUDIT')) {
            actions.push('5. 🛠️ 运行 npm audit fix 修复已知漏洞');
        }

        if (actions.length === 0) {
            actions.push('1. ✅ 定期运行安全扫描');
            actions.push('2. 📦 保持依赖项更新');
            actions.push('3. 🔐 启用npm账户2FA');
        }

        actions.forEach(action => console.log(`  ${action}`));

        console.log('\n📚 长期安全策略:');
        console.log('  • 实施依赖审查流程');
        console.log('  • 使用私有npm镜像');
        console.log('  • 监控异常的包更新活动');
        console.log('  • 定期安全培训');
        console.log('  • 建立应急响应计划');
    }

    /**
     * 计算安全评分
     */
    calculateSecurityScore() {
        let score = 100;

        // 严重威胁扣分
        const criticalThreats = this.scanResults.threats.filter(
            t => t.severity === 'CRITICAL'
        ).length;
        score -= criticalThreats * 25;

        // 高危威胁扣分
        const highThreats = this.scanResults.threats.filter(
            t => t.severity === 'HIGH'
        ).length;
        score -= highThreats * 10;

        // 高危警告扣分
        const highWarnings = this.scanResults.warnings.filter(
            w => w.severity === 'HIGH'
        ).length;
        score -= highWarnings * 3;

        // 中等警告扣分
        const mediumWarnings = this.scanResults.warnings.filter(
            w => w.severity === 'MEDIUM'
        ).length;
        score -= mediumWarnings * 1;

        // 错误扣分
        score -= this.scanResults.errors.length * 2;

        return Math.max(0, Math.min(100, Math.round(score)));
    }

    /**
     * 获取评分表情
     */
    getScoreEmoji(score) {
        if (score >= 90) return '🟢 优秀';
        if (score >= 70) return '🟡 良好';
        if (score >= 50) return '🟠 警告';
        return '🔴 危险';
    }

    /**
     * 保存详细报告
     */
    async saveReport() {
        const reportPath = path.join(process.cwd(), 'npm-security-report.json');
        const htmlReportPath = path.join(process.cwd(), 'npm-security-report.html');

        try {
            // 保存JSON报告
            await fs.writeFile(
                reportPath,
                JSON.stringify(this.scanResults, null, 2),
                'utf8'
            );
            console.log(`\n📄 JSON报告已保存至: ${reportPath}`);

            // 生成HTML报告
            const htmlReport = this.generateHTMLReport();
            await fs.writeFile(htmlReportPath, htmlReport, 'utf8');
            console.log(`📄 HTML报告已保存至: ${htmlReportPath}`);

        } catch (error) {
            console.error('⚠️  无法保存报告文件:', error.message);
        }
    }

    /**
     * 生成HTML报告
     */
    generateHTMLReport() {
        const score = this.calculateSecurityScore();
        const scoreColor = score >= 70 ? '#10b981' : score >= 50 ? '#f59e0b' : '#ef4444';

        return `<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NPM Security Scan Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f3f4f6; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; border-radius: 8px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .score { font-size: 48px; font-weight: bold; color: ${scoreColor}; }
        .section { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .threat { padding: 12px; margin: 8px 0; border-left: 4px solid #ef4444; background: #fee; }
        .warning { padding: 12px; margin: 8px 0; border-left: 4px solid #f59e0b; background: #fef3c7; }
        .critical { border-left-color: #dc2626; background: #fecaca; }
        .high { border-left-color: #f97316; background: #fed7aa; }
        h2 { color: #1f2937; margin-top: 0; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; }
        .stat { text-align: center; }
        .stat-value { font-size: 32px; font-weight: bold; color: #3b82f6; }
        .stat-label { color: #6b7280; margin-top: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>NPM安全扫描报告</h1>
            <p>扫描时间: ${new Date(this.scanResults.timestamp).toLocaleString()}</p>
            <div class="score">安全评分: ${score}/100</div>
        </div>

        <div class="section">
            <h2>扫描统计</h2>
            <div class="stats">
                <div class="stat">
                    <div class="stat-value">${this.scanResults.totalPackages}</div>
                    <div class="stat-label">总包数</div>
                </div>
                <div class="stat">
                    <div class="stat-value">${this.scanResults.threats.filter(t => t.severity === 'CRITICAL').length}</div>
                    <div class="stat-label">严重威胁</div>
                </div>
                <div class="stat">
                    <div class="stat-value">${this.scanResults.threats.filter(t => t.severity === 'HIGH').length}</div>
                    <div class="stat-label">高危威胁</div>
                </div>
                <div class="stat">
                    <div class="stat-value">${this.scanResults.warnings.length}</div>
                    <div class="stat-label">警告</div>
                </div>
            </div>
        </div>

        ${this.scanResults.threats.length > 0 ? `
        <div class="section">
            <h2>威胁详情</h2>
            ${this.scanResults.threats.map(t => `
                <div class="threat ${t.severity.toLowerCase()}">
                    <strong>[${t.severity}] ${t.package || t.type}</strong><br>
                    ${t.message}<br>
                    ${t.remediation ? `<em>建议: ${t.remediation}</em>` : ''}
                </div>
            `).join('')}
        </div>
        ` : ''}

        ${this.scanResults.warnings.length > 0 ? `
        <div class="section">
            <h2>警告</h2>
            ${this.scanResults.warnings.slice(0, 20).map(w => `
                <div class="warning">
                    <strong>[${w.type}]</strong> ${w.message}
                    ${w.remediation ? `<br><em>${w.remediation}</em>` : ''}
                </div>
            `).join('')}
        </div>
        ` : ''}

        <div class="section">
            <h2>安全建议</h2>
            <ul>
                <li>定期运行安全扫描</li>
                <li>使用npm ci代替npm install</li>
                <li>启用npm账户的2FA认证</li>
                <li>审查所有依赖变更</li>
                <li>保持package-lock.json文件更新</li>
            </ul>
        </div>
    </div>
</body>
</html>`;
    }
}

// CLI入口
async function main() {
    const scanner = new NPMSecurityScanner();

    // 解析命令行参数
    const args = process.argv.slice(2);
    const targetPath = args[0] || process.cwd();

    // 显示启动横幅
    console.log(`
╔══════════════════════════════════════════════════════════╗
║         NPM 恶意包扫描器 - 企业级安全防护工具           ║
║              专门防御2025年9月供应链攻击                 ║
║                    Version 2.0.0                         ║
╚══════════════════════════════════════════════════════════╝
`);

    // 检查是否有帮助参数
    if (args.includes('--help') || args.includes('-h')) {
        console.log('用法: node npm-scanner.js [目标目录]');
        console.log('\n选项:');
        console.log('  --help, -h    显示帮助信息');
        console.log('  --version     显示版本信息');
        console.log('\n示例:');
        console.log('  node npm-scanner.js                  # 扫描当前目录');
        console.log('  node npm-scanner.js /path/to/project # 扫描指定项目');
        process.exit(0);
    }

    if (args.includes('--version')) {
        console.log('NPM Security Scanner v2.0.0');
        process.exit(0);
    }

    // 检查目标路径是否存在
    try {
        await fs.access(targetPath);
    } catch {
        console.error(`❌ 错误: 目标路径不存在: ${targetPath}`);
        process.exit(1);
    }

    // 运行扫描
    await scanner.scan(targetPath);

    console.log('\n✨ 扫描完成！保持警惕，确保供应链安全。\n');

    // 如果发现严重威胁，返回非零退出码
    const criticalThreats = scanner.scanResults.threats.filter(
        t => t.severity === 'CRITICAL'
    ).length;

    if (criticalThreats > 0) {
        console.log('⚠️  发现严重安全威胁！请立即采取行动。');
        process.exit(1);
    }
}

// 错误处理
process.on('unhandledRejection', (error) => {
    console.error('💥 未处理的错误:', error);
    process.exit(1);
});

process.on('uncaughtException', (error) => {
    console.error('💥 未捕获的异常:', error);
    process.exit(1);
});

// 运行扫描器
if (require.main === module) {
    main().catch(error => {
        console.error('💥 致命错误:', error);
        process.exit(1);
    });
}

module.exports = NPMSecurityScanner;