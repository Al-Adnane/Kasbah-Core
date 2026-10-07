const http = require('http');

/**
 * Health check script for Docker containers
 * Returns exit code 0 if healthy, 1 if unhealthy
 */

const options = {
  hostname: 'localhost',
  port: process.env.PORT || 8788,
  path: '/v1/health',
  method: 'GET',
  timeout: 2000
};

const req = http.request(options, (res) => {
  if (res.statusCode === 200) {
    process.exit(0);
  } else {
    console.error(`Health check failed: status ${res.statusCode}`);
    process.exit(1);
  }
});

req.on('error', (err) => {
  console.error(`Health check error: ${err.message}`);
  process.exit(1);
});

req.on('timeout', () => {
  console.error('Health check timeout');
  req.destroy();
  process.exit(1);
});

req.end();
