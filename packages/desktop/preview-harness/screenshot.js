'use strict';
// Dev-only: renders the preview harness in an Electron window and saves a PNG.
const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');

app.whenReady().then(async () => {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    show: false,
    webPreferences: { nodeIntegration: false, contextIsolation: true, webviewTag: true },
  });

  win.webContents.on('console-message', (_e, level, message) => {
    console.log(`[console:${level}]`, message);
  });

  await win.loadFile(path.join(__dirname, 'index.html'));
  await new Promise((r) => setTimeout(r, 2500));

  try {
    const res = await win.webContents.executeJavaScript(`
      (function(){
        try {
          const el = document.getElementById('navBrowser');
          if (el) el.click();
          return {
            navFound: !!el,
            active: document.getElementById('pageBrowser')?.classList.contains('active') || false,
            pageDisplay: getComputedStyle(document.getElementById('pageBrowser')).display,
          };
        } catch (e) { return { error: e.message }; }
      })();
    `);
    console.log('nav result', JSON.stringify(res));
    await new Promise((r) => setTimeout(r, 500));
    await win.webContents.executeJavaScript(`bwrGo('about:blank');`);
  } catch (e) {
    console.error('script error', e.message);
  }

  await new Promise((r) => setTimeout(r, 1800));
  const image = await win.webContents.capturePage();
  const out = '/tmp/kasbah-preview.png';
  fs.writeFileSync(out, image.toPNG());
  console.log('screenshot saved to', out);
  app.quit();
});
