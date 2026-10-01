import http from 'k6/http';
import { check } from 'k6';

export const options = {
  vus: 50,
  duration: '3m',
  thresholds: {
    http_req_duration: ['p(99)<50'],  // 99% under 50ms
  },
};

export default function () {
  const payload = JSON.stringify({
    text: `Test ${Date.now()}: AKIAIOSFODNN7EXAMPLE`
  });

  const res = http.post(`${__ENV.API_URL || 'http://localhost:8000'}/api/scan`, payload, {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${__ENV.API_TOKEN || 'test-token'}`
    }
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'latency < 50ms': (r) => r.timings.duration < 50,
  });
}
