'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {createDecipheriv, createHash, randomBytes} = require('node:crypto');
const {gunzipSync} = require('node:zlib');

function install(model, key) {
  if (!/^\d{4}$/.test(model || '')) throw new Error('Informe o número do modelo.');
  if (!/^[a-f0-9]{64}$/i.test(key)) throw new Error('Código de instalação inválido.');

  const source = path.join(__dirname, 'exterior', model);
  const manifest = JSON.parse(fs.readFileSync(path.join(source, 'manifest.json'), 'utf8'));
  const parts = fs.readdirSync(source).filter(name => /^\d{2}\.enc$/.test(name)).sort();
  if (parts.length !== manifest.parts) throw new Error('Pacote incompleto. Atualize o catálogo pelo Git.');

  const encrypted = Buffer.concat(parts.map(name => fs.readFileSync(path.join(source, name))));
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key, 'hex'), encrypted.subarray(0, 12));
  decipher.setAuthTag(encrypted.subarray(12, 28));
  const compressed = Buffer.concat([decipher.update(encrypted.subarray(28)), decipher.final()]);
  const modelFile = gunzipSync(compressed, {maxOutputLength: manifest.bytes});
  const hash = createHash('sha256').update(modelFile).digest('hex');
  if (hash !== manifest.sha256 || modelFile.subarray(0, 4).toString() !== 'glTF' ||
      modelFile.readUInt32LE(4) !== 2 || modelFile.readUInt32LE(8) !== modelFile.length) {
    throw new Error('O arquivo 3D do pacote está inválido.');
  }

  const target = path.join(__dirname, '..', 'public', 'assets', 'exterior', model + '.glb');
  const temporary = target + '.' + randomBytes(8).toString('hex') + '.tmp';
  fs.mkdirSync(path.dirname(target), {recursive: true});
  try {
    fs.writeFileSync(temporary, modelFile, {flag: 'wx', mode: 0o644});
    fs.renameSync(temporary, target);
  } finally {
    fs.rmSync(temporary, {force: true});
  }
  console.log('Modelo ' + model + ' instalado no catálogo.');
}

try {
  install(process.argv[2], fs.readFileSync(0, 'utf8').trim());
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
