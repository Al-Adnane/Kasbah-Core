/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Proxy /api/kasbah/* → the running Kasbah engine.
  // In dev: http://127.0.0.1:8788 (local); in prod: env var KASBAH_API.
  async rewrites() {
    const target = process.env.KASBAH_API || 'http://127.0.0.1:8788';
    return [{ source: '/api/kasbah/:path*', destination: target + '/:path*' }];
  }
};
module.exports = nextConfig;
