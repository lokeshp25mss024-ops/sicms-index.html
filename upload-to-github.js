// upload-to-github.js - Direct GitHub API Uploader for SICMS
// Uploads all project files directly to https://github.com/lokeshp25mss024-ops/sicms-index.html
// Works even when git.exe is restricted by host Application Control policies.

const fs = require('node:fs');
const path = require('node:path');

const REPO_OWNER = 'lokeshp25mss024-ops';
const REPO_NAME = 'sicms-index.html';
const BRANCH = 'main';

// Pass your GitHub Personal Access Token as an argument or environment variable:
// e.g.: node upload-to-github.js ghp_yourPersonalAccessTokenHere
const GITHUB_TOKEN = process.argv[2] || process.env.GITHUB_TOKEN;

if (!GITHUB_TOKEN) {
  console.error('\n❌ ERROR: GitHub Personal Access Token is required.');
  console.log('Usage:');
  console.log('  node upload-to-github.js <YOUR_GITHUB_PERSONAL_ACCESS_TOKEN>\n');
  console.log('To generate a token:');
  console.log('  1. Go to https://github.com/settings/tokens?type=beta (or classic tokens: https://github.com/settings/tokens)');
  console.log('  2. Generate a token with "repo" or "Contents: Read & write" permission for lokeshp25mss024-ops/sicms-index.html.');
  console.log('  3. Re-run this script with the token.\n');
  process.exit(1);
}

const ROOT_DIR = __dirname;

// Files to upload
const FILES_TO_UPLOAD = [
  'README.md',
  'package.json',
  '.gitignore',
  'server.js',
  'db.js',
  'public/index.html',
  'public/css/style.css',
  'public/js/state.js',
  'public/js/api.js',
  'public/js/charts.js',
  'public/js/app.js',
  'public/bundle.js'
];

async function getExistingFileSha(filePath) {
  const url = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${filePath}?ref=${BRANCH}`;
  try {
    const res = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'User-Agent': 'SICMS-Uploader',
        'Accept': 'application/vnd.github.v3+json'
      }
    });
    if (res.ok) {
      const data = await res.json();
      return data.sha;
    }
    return null;
  } catch (err) {
    return null;
  }
}

async function uploadFile(relPath) {
  const fullPath = path.join(ROOT_DIR, relPath);
  if (!fs.existsSync(fullPath)) {
    console.warn(`⚠️ Skipping missing file: ${relPath}`);
    return;
  }

  const fileContent = fs.readFileSync(fullPath);
  const base64Content = fileContent.toString('base64');
  const existingSha = await getExistingFileSha(relPath);

  const payload = {
    message: existingSha ? `Update ${relPath}` : `Add ${relPath} - SICMS Sentinel`,
    content: base64Content,
    branch: BRANCH
  };

  if (existingSha) {
    payload.sha = existingSha;
  }

  const url = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${relPath}`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${GITHUB_TOKEN}`,
      'User-Agent': 'SICMS-Uploader',
      'Content-Type': 'application/json',
      'Accept': 'application/vnd.github.v3+json'
    },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    const errorData = await res.text();
    console.error(`❌ Failed to upload ${relPath} (Status ${res.status}): ${errorData}`);
    return false;
  }

  const result = await res.json();
  console.log(`✅ Uploaded: ${relPath} (commit: ${result.commit.sha.substring(0, 7)})`);
  return true;
}

async function main() {
  console.log(`\n🚀 Starting upload to GitHub repository: https://github.com/${REPO_OWNER}/${REPO_NAME} (branch: ${BRANCH})\n`);

  let successCount = 0;
  for (const file of FILES_TO_UPLOAD) {
    process.stdout.write(`Uploading ${file}... `);
    const ok = await uploadFile(file);
    if (ok) successCount++;
  }

  console.log(`\n🎉 Completed! Successfully uploaded ${successCount}/${FILES_TO_UPLOAD.length} files.`);
  console.log(`🔗 View your repository: https://github.com/${REPO_OWNER}/${REPO_NAME}\n`);
}

main().catch(err => {
  console.error('Fatal error during upload:', err);
  process.exit(1);
});
