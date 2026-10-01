import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const detectionLatency = new Rate('detection_under_100ms');

export const options = {
  stages: [
    { duration: '2m', target: 100 },   // Ramp to 100 users
    { duration: '3m', target: 500 },   // Ramp to 500 users
    { duration: '5m', target: 500 },   // Stay at 500 users
    { duration: '2m', target: 0 },     // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],  // 95% under 500ms
    http_req_failed: ['rate<0.01'],    // Error rate <1%
    errors: ['rate<0.01'],             // Custom error rate <1%
    detection_under_100ms: ['rate>0.95'] // 95% under 100ms
  },
};

export default function () {
  const payload = JSON.stringify({
    text: 'AKIAIOSFODNN7EXAMPLE'
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${__ENV.API_TOKEN || 'test-token'}`
    }
  };

  const res = http.post(`${__ENV.API_URL || 'http://localhost:8000'}/api/scan`, payload, params);
  
  const success = check(res, {
    'status is 200': (r) => r.status === 200,
    'has risk score': (r) => JSON.parse(r.body).risk !== undefined,
    'latency < 100ms': (r) => r.timings.duration < 100,
  });

  errorRate.add(!success);
  detectionLatency.add(res.timings.duration < 100);
  
  sleep(1);
}
