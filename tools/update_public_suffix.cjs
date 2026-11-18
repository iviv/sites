#!/usr/bin/env node
// Rebuilds the rule data in v2_public_suffix.js from a copy of the Public Suffix List.
//
//   curl -o public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat
//   node tools/update_public_suffix.cjs public_suffix_list.dat
//
// Rules are stored in ASCII (punycode) form, since that's how domains appear in mail headers.
const fs = require('node:fs');
const path = require('node:path');
const { domainToASCII } = require('node:url');

const source = process.argv[2];
if (!source) {
  console.error('Usage: node tools/update_public_suffix.cjs <public_suffix_list.dat>');
  process.exit(1);
}
const text = fs.readFileSync(source, 'utf8');
const version = text.match(/^\/\/ VERSION: (\S+)/m)?.[1] || 'unknown';
const sections = { icann: [], private: [] };
let section = null;
for (const line of text.split(/\r?\n/)) {
  if (line.includes('===BEGIN ICANN DOMAINS===')) section = 'icann';
  else if (line.includes('===BEGIN PRIVATE DOMAINS===')) section = 'private';
  else if (/===END (ICANN|PRIVATE) DOMAINS===/.test(line)) section = null;
  const rule = line.trim().split(/\s/)[0];
  if (!section || !rule || rule.startsWith('//')) continue;
  const exception = rule.startsWith('!');
  const labels = rule.slice(exception ? 1 : 0).split('.').map(label => label === '*' ? label : domainToASCII(label));
  if (labels.some(label => !label)) throw new Error('Could not convert rule: ' + rule);
  sections[section].push((exception ? '!' : '') + labels.join('.').toLowerCase());
}
if (sections.icann.length < 5000 || sections.private.length < 1000) throw new Error('The list looks incomplete');

const target = path.join(__dirname, '..', 'v2_public_suffix.js');
const current = fs.readFileSync(target, 'utf8');
const data = [
  '  // BEGIN GENERATED DATA (tools/update_public_suffix.cjs)',
  `  const listVersion = ${JSON.stringify(version)};`,
  `  const icannRules = ${JSON.stringify(sections.icann.join(' '))};`,
  `  const privateRules = ${JSON.stringify(sections.private.join(' '))};`,
  '  // END GENERATED DATA'
].join('\n');
const updated = current.replace(/  \/\/ BEGIN GENERATED DATA[\s\S]*?\/\/ END GENERATED DATA/, data);
if (updated === current && !current.includes(data)) throw new Error('Data markers not found in ' + target);
fs.writeFileSync(target, updated);
console.log(`Wrote ${sections.icann.length} ICANN and ${sections.private.length} private rules (list ${version}).`);
