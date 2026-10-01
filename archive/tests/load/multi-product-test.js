import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '5m', target: 200 },  // 200 users per product
  ],
};

export default function () {
  const scenarios = [
    { name: 'slack', url: '/api/slack/scan', weight: 0.3 },
    { name: 'discord', url: '/api/discord/scan', weight: 0.3 },
    { name: 'hospital', url: '/api/hipaa/scan', weight: 0.2 },
    { name: 'legal', url: '/api/legal/scan', weight: 0.2 },
  ];

  const scenario = selectScenario(scenarios);
  
  const payload = JSON.stringify({
    content: `Test ${scenario.name}: ${Date.now()}`
  });

  const res = http.post(`${__ENV.API_URL || 'http://localhost:8000'}${scenario.url}`, payload, {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${__ENV.API_TOKEN || 'test-token'}`
    }
  });

  check(res, {
    [`${scenario.name} - status 200`]: (r) => r.status === 200,
    [`${scenario.name} - latency < 200ms`]: (r) => r.timings.duration < 200,
  });

  sleep(1);
}

function selectScenario(scenarios) {
  const rand = Math.random();
  let cumulative = 0;
  for (const s of scenarios) {
    cumulative += s.weight;
    if (rand < cumulative) return s;
  }
  return scenarios[scenarios.length - 1];
}
