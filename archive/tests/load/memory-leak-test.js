import { Trend } from 'k6/metrics';

const memoryUsage = new Trend('memory_usage_mb');

export const options = {
  duration: '10m',
  vus: 100,
};

export default function () {
  // Continuous load for 10 minutes
  const res = http.post(`${__ENV.API_URL || 'http://localhost:8000'}/api/scan`, JSON.stringify({
    text: 'Test for memory leak'
  }), {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${__ENV.API_TOKEN || 'test-token'}`
    }
  });

  // Report memory usage (via custom endpoint)
  const metrics = http.get(`${__ENV.API_URL || 'http://localhost:8000'}/metrics`);
  const memory = parseMemory(metrics.body);
  memoryUsage.add(memory);
}

function parseMemory(metricsBody) {
  // Parse Prometheus-style metrics
  const match = metricsBody.match(/process_resident_memory_bytes (\d+)/);
  return match ? parseFloat(match[1]) / 1024 / 1024 : 0;
}
