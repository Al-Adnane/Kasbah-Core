/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  images: {
    domains: ['api.kasbah.ai']
  },
  env: {
    KASBAH_API_URL: process.env.KASBAH_API_URL || 'http://127.0.0.1:8788'
  }
}

module.exports = nextConfig
