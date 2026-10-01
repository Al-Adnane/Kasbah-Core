const fs=require('fs');
let s=fs.readFileSync('server.js','utf8');
s=s.replace(/kasbahProducts\./g,'getKasbahProducts().');
fs.writeFileSync('server.js',s);
console.log('OK');
