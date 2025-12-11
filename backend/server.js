const express = require('express');
const cors = require('cors');
const { PentestEngine } = require('./core-attack-engine');

const app = express();
app.use(express.json());
app.use(cors());

// Store ongoing scans
const scanResults = new Map();

app.post('/api/scan', async (req, res) => {
  const { domain } = req. body;

  if (!domain) {
    return res.status(400).json({ error: 'Domain required' });
  }

  try {
    console.log(`\n🚀 Starting aggressive scan on:  ${domain}\n`);

    const engine = new PentestEngine(domain);
    const report = await engine.runFullAttack();

    // Store result
    scanResults.set(domain, report);

    res.json(report);

  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ 
      error: 'Scan failed',
      message: error.message 
    });
  }
});

app.get('/api/results/:domain', (req, res) => {
  const result = scanResults.get(req. params.domain);
  
  if (!result) {
    return res.status(404).json({ error: 'No results found' });
  }

  res.json(result);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`\n🔥 Pentest Engine running on port ${PORT}\n`);
});
