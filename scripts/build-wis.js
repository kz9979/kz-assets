#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const sourcePath = path.join(root, 'src', 'web-integrity-shield-v1.0.js');
const distPath = path.join(root, 'dist', 'web-integrity-shield-v1.0.min.js');

function compactJavaScript(input) {
  return input
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/\s+/g, ' ')
    .replace(/\s*([{}()[\];,:?+*\/%<>=!&|.-])\s*/g, '$1')
    .replace(/;}/g, '}')
    .trim();
}

function toHexEscapedBase64(input) {
  return Buffer.from(input, 'utf8')
    .toString('base64')
    .match(/.{1,64}/g)
    .map((chunk) => chunk.split('').map((char) => `\\x${char.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''));
}

const compact = compactJavaScript(fs.readFileSync(sourcePath, 'utf8'));
const encodedChunks = toHexEscapedBase64(compact).reverse();
const dist = `function _0x4f2a(){var _0x2f9d=${JSON.stringify(encodedChunks)};return _0x4f2a=function(){return _0x2f9d},_0x4f2a()}(function(_0x188c,_0x52da){var _0x3457=function(_0x51df){return typeof atob==='function'?atob(_0x51df):Buffer.from(_0x51df,'base64').toString('binary')},_0x1f03=_0x188c();_0x1f03.reverse();var _0x58bb=_0x3457(_0x1f03.join('')),_0x3f63='',_0x496d=0;for(;_0x496d<_0x58bb.length;_0x496d++){_0x3f63+=String.fromCharCode(_0x58bb.charCodeAt(_0x496d))}Function(_0x3f63)()})(_0x4f2a);`;

fs.writeFileSync(distPath, dist + '\n');
console.log(`Built ${path.relative(root, distPath)} from ${path.relative(root, sourcePath)} (${dist.length} bytes).`);
