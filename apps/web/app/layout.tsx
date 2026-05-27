import './globals.css';
import type { Metadata, Viewport } from 'next';
import Link from 'next/link';
import { LogoMark } from '../components/Logo';

export const metadata: Metadata = {
  title: 'Kasbah — The Trust Layer for Agentic AI',
  description: 'Every AI action signed. Every receipt verifiable. Kasbah runs under your agents and emits a cryptographic audit trail you did not have to build.',
  metadataBase: new URL('https://bekasbah.com'),
  openGraph: {
    title: 'Kasbah — The Trust Layer for Agentic AI',
    description: 'Every AI action signed. Every receipt verifiable.',
    url: 'https://bekasbah.com',
    siteName: 'Kasbah',
    type: 'website'
  }
};

export const viewport: Viewport = {
  themeColor: '#FEFCFA',
  width: 'device-width',
  initialScale: 1
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap"
          rel="stylesheet"
        />
        <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' ry='14' fill='%23C1440E'/%3E%3Cg transform='translate(16,16) scale(2)' fill='%23fff'%3E%3Cpath d='M9.25 7.25C9.25 7.76 8.94 8.2 8.5 8.4V9.5C8.5 9.78 8.28 10 8 10C7.72 10 7.5 9.78 7.5 9.5V8.4C7.06 8.2 6.75 7.76 6.75 7.25C6.75 6.56 7.31 6 8 6C8.69 6 9.25 6.56 9.25 7.25ZM7.14 2.04C6.78 2.29 6.22 2.62 5.42 2.92C4.64 3.22 3.9 3.36 3.36 3.43C3.09 3.47 2.88 3.49 2.73 3.49C2.65 3.5 2.59 3.5 2.56 3.5L2.5 3.5C2.37 3.5 2.24 3.55 2.15 3.64C2.05 3.74 2 3.87 2 4V6.76C2 9.41 3.4 11.86 5.69 13.21L7.75 14.43C7.9 14.52 8.1 14.52 8.26 14.43L10.32 13.21C12.6 11.86 14 9.41 14 6.76V4C14 3.87 13.95 3.74 13.85 3.64C13.76 3.55 13.63 3.5 13.49 3.5L13.44 3.5C13.4 3.5 13.35 3.5 13.27 3.49C13.12 3.49 12.91 3.47 12.64 3.44C12.1 3.37 11.37 3.22 10.59 2.92C9.8 2.61 9.23 2.28 8.86 2.04C8.68 1.91 8.55 1.81 8.46 1.74C8.43 1.71 8.39 1.68 8.35 1.64C8.26 1.55 8.13 1.5 8 1.5C7.87 1.5 7.74 1.55 7.65 1.65L7.54 1.75C7.45 1.82 7.32 1.92 7.14 2.04ZM3 6.76V4.48C3.14 4.47 3.31 4.45 3.49 4.42C4.09 4.35 4.91 4.18 5.78 3.85C6.65 3.52 7.28 3.16 7.71 2.87C7.82 2.79 7.92 2.72 8 2.65C8.09 2.72 8.19 2.79 8.3 2.87C8.73 3.15 9.36 3.52 10.23 3.85C11.1 4.19 11.91 4.35 12.51 4.43C12.69 4.45 12.86 4.47 13 4.48V6.76C13 9.05 11.79 11.18 9.81 12.35L8 13.42L6.19 12.35C4.21 11.18 3 9.05 3 6.76Z'/%3E%3C/g%3E%3C/svg%3E" />
      </head>
      <body>
        <nav className="nav">
          <div className="nav-inner">
            <Link href="/" className="nav-brand">
              <LogoMark size={32} />
              <span>Kasbah</span>
            </Link>
            <div className="nav-links">
              <Link href="/#cases">Use cases</Link>
              <Link href="/#developers">Developers</Link>
              <Link href="/#measured">Measured</Link>
              <Link href="/verify">Verify</Link>
              <Link href="/dashboard">Live</Link>
              <a href="https://github.com/Al-Adnane/Kasbah-Core" target="_blank" rel="noopener">GitHub</a>
            </div>
            <Link href="/#cases" className="nav-cta">Try it →</Link>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
