// Add this toggle to docs/index.html

const USE_REAL_API = false; // Toggle this
const API_URL = USE_REAL_API ? 'https://your-api.railway.app' : null;

async function runSafe() {
  const btn = document.getElementById('btn-safe');
  btn.disabled = true;
  btn.textContent = 'Running...';
  
  out('out1', '⏳ Requesting permission...');
  await sleep(500);
  
  if (USE_REAL_API) {
    // Call real API
    const response = await fetch(`${API_URL}/api/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool: 'db.query',
        agent_id: 'demo',
        signals: { consistency: 0.95, accuracy: 0.98 }
      })
    });
    
    const data = await response.json();
    savedTicket = data.ticket;
    
    out('out1',
      `✓ REAL API CALL\n\n` +
      `Integrity: ${data.integrity}\n` +
      `Ticket: ${data.ticket.substring(0, 40)}...\n` +
      `Latency: ${Date.now() - startTime}ms\n\n` +
      `⏳ Consuming ticket...`,
    );
    
    const consumeResponse = await fetch(`${API_URL}/api/consume`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ticket: data.ticket,
        tool: 'db.query'
      })
    });
    
    const consumeData = await consumeResponse.json();
    
    out('out1',
      `✓ REAL API CALL\n\n` +
      `Integrity: ${data.integrity}\n` +
      `Ticket: ${data.ticket.substring(0, 40)}...\n` +
      `Total latency: ${Date.now() - startTime}ms\n\n` +
      `✓ Entry granted\n` +
      `Status: ${consumeResponse.status}\n` +
      `Consumed: ${consumeData.consumed}\n\n` +
      `💡 This was a REAL backend call!`,
      'success'
    );
  } else {
    // Existing simulated code
    // ...
  }
  
  btn.disabled = false;
  btn.textContent = 'Run safe flow';
}
