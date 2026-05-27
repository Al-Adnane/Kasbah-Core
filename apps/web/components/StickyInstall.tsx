'use client';

// Sticky install CTA that appears after the visitor scrolls past the hero.
// One-click path to the install section, follows them anywhere on the page.

import { useEffect, useState } from 'react';

export function StickyInstall() {
  const [show, setShow] = useState(false);

  useEffect(() => {
    const onScroll = () => {
      // Show after scrolling 600px (past the hero dashboard)
      // Hide near the install section so it doesn't double up
      const y = window.scrollY;
      const installEl = document.getElementById('install-mcp');
      const installY = installEl?.getBoundingClientRect().top ?? Infinity;
      setShow(y > 600 && installY > 120);
    };
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <a
      href="#install-mcp"
      className={'sticky-install' + (show ? ' show' : '')}
      aria-label="Install Kasbah MCP"
    >
      <span className="sticky-install-glyph">⌘</span>
      <span className="sticky-install-text">
        <strong>Install MCP</strong>
        <span>1 line · 60 seconds</span>
      </span>
      <span className="sticky-install-arrow">→</span>
    </a>
  );
}
