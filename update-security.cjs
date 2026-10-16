const { createPublicKey, verify, createHash } = require('node:crypto');
const fs = require('node:fs/promises');
const { TextDecoder } = require('node:util');

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
}
function decodeBase64(value, size) {
  if (typeof value !== 'string' || value.length > 32768 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('Invalid Base64');
  const bytes = Buffer.from(value,'base64');
  if (bytes.toString('base64') !== value || (size !== undefined && bytes.length !== size)) throw new Error('Invalid Base64');
  return bytes;
}
function versionParts(value) {
  if (typeof value !== 'string' || value.length > 64 || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value)) throw new Error('Invalid stable version');
  const parts=value.split('.').map(Number);
  if (!parts.every(Number.isSafeInteger)) throw new Error('Invalid stable version');
  return parts;
}
function compareVersions(a,b) {
  const left=versionParts(a), right=versionParts(b);
  for(let i=0;i<3;i++) if(left[i]!==right[i]) return left[i]>right[i]?1:-1;
  return 0;
}
function validateReleaseConfig(config) {
  if (!exactKeys(config,['provider','url','publisherName','publicKey','publishableKey']) || config.provider!=='generic' || typeof config.url!=='string' || !/^https:\/\/[a-z0-9]{20}\.supabase\.co\/functions\/v1\/desktop-update\/$/.test(config.url)) throw new Error('Invalid release configuration');
  if (!Array.isArray(config.publisherName) || config.publisherName.length!==1 || config.publisherName[0]!=='AI Team Village release') throw new Error('Invalid release publisher');
  if (typeof config.publicKey!=='string' || config.publicKey.length>2048 || !config.publicKey.startsWith('-----BEGIN PUBLIC KEY-----\n') || createPublicKey(config.publicKey).asymmetricKeyType!=='ed25519') throw new Error('Invalid release signing key');
  const key=config.publishableKey;
  let publicKey=typeof key==='string' && /^sb_publishable_[A-Za-z0-9_-]{10,200}$/.test(key);
  if(!publicKey && typeof key==='string' && key.length<=4096 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(key)) {
    try { publicKey=JSON.parse(Buffer.from(key.split('.')[1],'base64url').toString('utf8')).role==='anon'; } catch {}
  }
  if(!publicKey) throw new Error('Invalid release public auth key');
  return config;
}
function verifyManifest(envelope, publicKey) {
  if (!exactKeys(envelope,['payload','signature'])) throw new Error('Invalid release envelope');
  const payload=decodeBase64(envelope.payload), signature=decodeBase64(envelope.signature,64);
  const key=createPublicKey(publicKey);
  if(key.asymmetricKeyType!=='ed25519' || !verify(null,payload,key,signature)) throw new Error('Invalid release signature');
  const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(payload));
  if(!exactKeys(value,['format','version','filename','sha512','size','parts']) || value.format!==1) throw new Error('Invalid release manifest');
  versionParts(value.version);
  if(value.filename!==`AI-Team-Village-${value.version}-Setup.exe` || !Number.isSafeInteger(value.size) || value.size<1 || value.size>268435456) throw new Error('Invalid release installer');
  decodeBase64(value.sha512,64);
  if(!Array.isArray(value.parts) || value.parts.length<1 || value.parts.length>6) throw new Error('Invalid release parts');
  let size=0;
  value.parts.forEach((part,index)=>{
    if(!exactKeys(part,['path','size']) || part.path!==`releases/${value.version}/${value.filename}.part-${index}` || !Number.isSafeInteger(part.size) || part.size<1 || part.size>50331648) throw new Error('Invalid release part');
    size+=part.size;
    Object.freeze(part);
  });
  if(size!==value.size) throw new Error('Invalid release size');
  Object.freeze(value.parts);
  return Object.freeze(value);
}
function validateMetadata(info,manifest) {
  const allowed=['version','files','path','sha512','releaseDate'];
  if(!info || typeof info!=='object' || Array.isArray(info) || Object.keys(info).some(key=>!allowed.includes(key)) || info.version!==manifest.version || !Array.isArray(info.files) || info.files.length!==1) throw new Error('Update metadata mismatch');
  const file=info.files[0];
  if(!exactKeys(file,['url','sha512','size']) || file.url!==manifest.filename || file.sha512!==manifest.sha512 || file.size!==manifest.size || (info.path!==undefined && info.path!==manifest.filename) || (info.sha512!==undefined && info.sha512!==manifest.sha512)) throw new Error('Update installer mismatch');
}
async function verifyInstaller(file,manifest,signal) {
  signal?.throwIfAborted();
  if(typeof file!=='string') throw new Error('Invalid installer file');
  const stat=await fs.lstat(file);
  if(!stat.isFile() || stat.size!==manifest.size) throw new Error('Invalid installer size');
  const handle=await fs.open(file,'r');
  try {
    const opened=await handle.stat();
    if(!opened.isFile() || opened.size!==manifest.size) throw new Error('Invalid installer file');
    const hash=createHash('sha512'); let size=0;
    for await (const chunk of handle.createReadStream({autoClose:false,signal})) {
      size+=chunk.length;
      if(size>manifest.size) throw new Error('Installer changed during verification');
      hash.update(chunk);
    }
    signal?.throwIfAborted();
    const after=await fs.lstat(file);
    if(size!==manifest.size || hash.digest('base64')!==manifest.sha512 || !after.isFile() || after.size!==opened.size || after.ino!==opened.ino || after.mtimeMs!==opened.mtimeMs) throw new Error('Installer integrity check failed');
  } finally { await handle.close(); }
}
module.exports={validateReleaseConfig,verifyManifest,validateMetadata,verifyInstaller,compareVersions};
