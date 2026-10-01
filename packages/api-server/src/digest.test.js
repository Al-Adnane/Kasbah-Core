'use strict';
const assert = require('assert');
const intervention = require('./intervention.js');
const digest = require('./digest.js');

intervention.reset('digest-test');
intervention.decide({ risk: 0.1, clientKey: 'digest-test' });
intervention.decide({ risk: 0.95, threats: ['secret:aws'], clientKey: 'digest-test' });
const d = digest.build('digest-test', { period: 'week', receiptCount: 1, trustGrade: { grade: 'A', score: 92, label: 'Fortress' } });
assert.ok(/saved you/i.test(d.headline + d.lines.join(' ')));
assert.ok(d.slack?.blocks?.length >= 2);
assert.ok(d.email?.bodyHtml.includes('Kasbah'));
assert.ok(d.footer.includes('Kasbah'));
assert.strictEqual(d.period, 'week');
console.log('digest OK:', d.headline);
