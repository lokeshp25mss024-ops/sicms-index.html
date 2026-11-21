const fs = require('fs');
const path = require('path');

const htmlPath = path.resolve(__dirname, '../../brain/98af1b7c-10ad-494a-b3bd-7f13ae1457c7/sicms-app.html');
const bundlePath = path.resolve(__dirname, 'public/bundle.js');

let html = fs.readFileSync(htmlPath, 'utf8');
const bundle = fs.readFileSync(bundlePath, 'utf8');

const splitMarker = '<!-- Include Scripts Directly';
if (html.includes(splitMarker)) {
  const parts = html.split(splitMarker);
  const endParts = parts[1].split('</body>');
  const newHtml = parts[0] + '<script>\n' + bundle + '\n</script>\n</body>' + endParts[1];
  fs.writeFileSync(htmlPath, newHtml, 'utf8');
  console.log('Artifact successfully compiled into standalone self-contained HTML.');
} else {
  console.log('Split marker not found, already inlined?');
}
