import { useState } from 'react';
import styles from '../styles/Home.module.css';

export default function Home() {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function scanDomain() {
    if (!domain) {
      alert('Enter a domain');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const cleanDomain = domain
        .replace('https://', '')
        .replace('http://', '')
        .split('/')[0];

      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: cleanDomain })
      });

      const data = await response.json();
      setResult(data);
    } catch (error) {
      setResult({ error: error.message });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className={styles.container}>
      <h1>🔴 AGGRESSIVE DOMAIN SCANNER</h1>
      <p>Advanced penetration testing for email extraction</p>

      <div className={styles.inputGroup}>
        <input
          type="text"
          placeholder="secure.serve.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && scanDomain()}
          className={styles.input}
        />
        <button onClick={scanDomain} disabled={loading} className={styles.button}>
          {loading ? '⏳ SCANNING...' : '🔥 ATTACK'}
        </button>
      </div>

      {result && (
        <div className={styles. results}>
          {result.error ?  (
            <div className={styles.error}>❌ {result.error}</div>
          ) : (
            <>
              <div className={`${styles.section} ${styles[result.severity. toLowerCase()]}`}>
                <h2>⚠️ SEVERITY:  {result.severity}</h2>
                <p>Confidence:  {result.confidence}%</p>
              </div>

              <div className={styles.section}>
                <h2>🚨 Vulnerabilities Found:  {result.totalVulnerabilities}</h2>
                {result.vulnerabilities.map((vuln, i) => (
                  <div key={i} className={`${styles.vuln} ${styles[vuln.severity.toLowerCase()]}`}>
                    <strong>[{vuln.severity}] {vuln.type}</strong>
                    <p>{vuln.details || vuln.endpoint}</p>
                  </div>
                ))}
              </div>

              <div className={styles.section}>
                <h2>📧 EMAILS EXTRACTED: {result.emailCount}</h2>
                {result.emailCount > 0 ?  (
                  <div className={styles.emailList}>
                    {result. emailsExtracted.slice(0, 50).map((email, i) => (
                      <div key={i} className={styles.email}>
                        {email}
                      </div>
                    ))}
                    {result.emailCount > 50 && (
                      <p style={{ color: '#ff6b6b', fontWeight: 'bold' }}>
                        ... and {result. emailCount - 50} more emails
                      </p>
                    )}
                  </div>
                ) : (
                  <p style={{ color: '#51cf66' }}>✅ No emails extracted</p>
                )}
              </div>

              <div className={styles.section}>
                <h2>📋 Full Report</h2>
                <pre className={styles.json}>
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
