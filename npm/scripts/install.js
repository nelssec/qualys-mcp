#!/usr/bin/env node

const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const packageJson = require('../package.json');
const VERSION = packageJson.version;
const REPO = 'nelssec/qualys-mcp';

function getPlatform() {
  const platform = process.platform;
  const arch = process.arch;

  const platformMap = {
    darwin: 'darwin',
    linux: 'linux',
    win32: 'windows',
  };

  const archMap = {
    x64: 'amd64',
    arm64: 'arm64',
  };

  const os = platformMap[platform];
  const cpu = archMap[arch];

  if (!os || !cpu) {
    throw new Error(`Unsupported platform: ${platform}-${arch}`);
  }

  return { os, cpu, ext: platform === 'win32' ? '.exe' : '' };
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);

    const request = (url) => {
      https.get(url, (response) => {
        if (response.statusCode === 302 || response.statusCode === 301) {
          request(response.headers.location);
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(`Failed to download: ${response.statusCode}`));
          return;
        }

        response.pipe(file);
        file.on('finish', () => {
          file.close();
          resolve();
        });
      }).on('error', (err) => {
        fs.unlink(dest, () => {});
        reject(err);
      });
    };

    request(url);
  });
}

async function install() {
  const { os, cpu, ext } = getPlatform();
  const binName = `qualys-mcp-${os}-${cpu}${ext}`;
  const binDir = path.join(__dirname, '..', 'bin');
  const binPath = path.join(binDir, binName);

  if (fs.existsSync(binPath)) {
    const stats = fs.statSync(binPath);
    if (stats.size > 1000000) {
      console.log('qualys-mcp binary already exists');
      return;
    }
  }

  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  const assetName = `qualys-mcp-${os}-${cpu}${ext}`;
  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/${assetName}`;

  console.log(`Downloading qualys-mcp for ${os}-${cpu}...`);
  console.log(`URL: ${url}`);

  try {
    await downloadFile(url, binPath);
    fs.chmodSync(binPath, 0o755);
    console.log('qualys-mcp installed successfully!');
  } catch (err) {
    console.error(`Failed to download binary: ${err.message}`);
    console.error('');
    console.error('You can build from source instead:');
    console.error('  git clone https://github.com/nelssec/qualys-mcp');
    console.error('  cd qualys-mcp && go build -o qualys-mcp ./cmd/qualys-mcp');
    process.exit(1);
  }
}

install().catch((err) => {
  console.error(err);
  process.exit(1);
});
