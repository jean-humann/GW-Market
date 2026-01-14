# GW-Market Security Review

**Repository:** GW-Market (https://gwmarket.net/shop)
**Review Date:** 2026-01-14
**Reviewer:** Claude Security Analysis
**Application Type:** Full-stack Guild Wars 1 Player Marketplace
**Tech Stack:** Node.js/Express (Backend), Angular 18 (Frontend), Socket.io (Real-time), MongoDB (Production DB)

---

## Executive Summary

This security review identifies **16 security vulnerabilities** across the GW-Market codebase, ranging from **Critical** to **Low** severity. The application is a real-time marketplace for Guild Wars 1 players to trade items. While the codebase demonstrates some security awareness (input validation, field sanitization), several significant vulnerabilities exist that should be addressed before or after public deployment.

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 4 |
| Medium | 6 |
| Low | 4 |

---

## Critical Vulnerabilities

### 1. Path Traversal in Static Asset Route
**Location:** `server/app.ts:52-54`
**Severity:** CRITICAL
**CVSS Score:** 9.1

```typescript
app.get('/assets/*', function (req, res) {
  var reqpath = req.url.toString().split('?')[0].split('/').slice(2).join('/');
  res.sendFile(path.join(process.cwd(), '../assets', reqpath));
});
```

**Issue:** The asset route constructs file paths from user input without proper sanitization. An attacker can use path traversal sequences to read arbitrary files from the server.

**Attack Vector:**
```
GET /assets/../../server/.env HTTP/1.1
GET /assets/../../etc/passwd HTTP/1.1
GET /assets/../../../.ssh/id_rsa HTTP/1.1
```

**Impact:** Full server filesystem read access, exposure of environment variables, secrets, SSH keys, and other sensitive files.

**Recommendation:**
```typescript
import { basename, resolve, normalize } from 'path';

app.get('/assets/*', function (req, res) {
  const requestedPath = req.params[0];
  const safePath = normalize(requestedPath).replace(/^(\.\.(\/|\\|$))+/, '');
  const fullPath = resolve(process.cwd(), '../assets', safePath);
  const assetsDir = resolve(process.cwd(), '../assets');

  if (!fullPath.startsWith(assetsDir)) {
    return res.status(403).send('Forbidden');
  }
  res.sendFile(fullPath);
});
```

---

### 2. No Authentication on Socket.io Operations
**Location:** `server/src/services/socket.service.ts:16-75`
**Severity:** CRITICAL
**CVSS Score:** 9.8

**Issue:** All Socket.io events are completely unauthenticated. Any client can:
- Create/modify/delete shops for any UUID
- Impersonate any player name
- Close any shop by UUID
- Flood the system with fake shops

```typescript
socket.on('refreshShop', (shop: Shop) => {
  ShopService.refreshShop(shop, socket);  // No auth check
});

socket.on('closeShop', (uuid: string) => {
  ShopService.closeShop(uuid);  // No auth check - anyone can close any shop!
});
```

**Impact:** Complete marketplace manipulation, shop takeover, denial of service through shop flooding.

**Recommendation:**
- Implement JWT or session-based authentication for Socket.io
- Use socket.io middleware for authentication
- Require shop ownership verification before modifications
- Add rate limiting per IP/socket

---

## High Severity Vulnerabilities

### 3. No Rate Limiting
**Location:** Server-wide
**Severity:** HIGH
**CVSS Score:** 7.5

**Issue:** No rate limiting exists on any endpoint or socket event. This enables:
- Brute force attacks on any future authentication
- DoS through request flooding
- Resource exhaustion attacks
- Shop/order spam flooding

**Recommendation:**
```typescript
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Socket.io rate limiting
const socketRateLimiter = new Map();
socket.use((socket, next) => {
  const ip = socket.handshake.address;
  // Implement rate limiting logic
});
```

---

### 4. Unsafe JSON.parse Without Validation
**Location:** `client/src/app/pages/shop/shop.component.ts:234-237`
**Severity:** HIGH
**CVSS Score:** 7.2

```typescript
reader.onload = (e): void => {
  const content = reader.result as string;
  const importedShop = JSON.parse(content) as Shop;  // No validation!
  this.shopService.importShop(importedShop);
};
```

**Issue:** Imported JSON shop files are parsed and used without any validation. Malicious JSON files could contain:
- Prototype pollution payloads
- Oversized arrays causing memory exhaustion
- Invalid data types causing application crashes

**Recommendation:**
```typescript
import Ajv from 'ajv';
const ajv = new Ajv();
const shopSchema = { /* JSON Schema */ };
const validate = ajv.compile(shopSchema);

if (validate(importedShop)) {
  this.shopService.importShop(importedShop);
} else {
  this.toastrService.error('Invalid shop file format');
}
```

---

### 5. Client-Controlled Navigation Vulnerability
**Location:** `client/src/app/services/util.service.ts:32-34`
**Severity:** HIGH
**CVSS Score:** 7.1

```typescript
this.socket.on('ClientRedirect', (url: string[]) => {
  this.router.navigate(url);
});
```

**Issue:** The server can instruct the client to navigate anywhere. If the server is compromised or a malicious server is used, it could redirect users to phishing pages or trigger unintended actions.

**Recommendation:**
- Validate redirect URLs against a whitelist
- Only allow internal route navigation
- Remove this feature if not essential

---

### 6. Missing Security Headers
**Location:** `server/app.ts`
**Severity:** HIGH
**CVSS Score:** 6.5

**Issue:** No security headers are configured:
- No Content-Security-Policy (CSP)
- No X-Frame-Options (Clickjacking protection)
- No X-Content-Type-Options
- No Strict-Transport-Security (HSTS)
- No X-XSS-Protection

**Recommendation:**
```typescript
import helmet from 'helmet';
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "blob:"],
    connectSrc: ["'self'", "wss:", "ws:"]
  }
}));
```

---

## Medium Severity Vulnerabilities

### 7. Sensitive Data in Client-Side Storage
**Location:** `client/src/app/services/store.service.ts:68-70`
**Severity:** MEDIUM
**CVSS Score:** 5.3

```typescript
const password = localStorage.getItem('password');
this.socket.emit(field, password, option);
```

**Issue:** Passwords are stored in localStorage, which is:
- Accessible to any JavaScript on the page (XSS vector)
- Persists indefinitely
- Not encrypted
- Accessible via browser developer tools

**Recommendation:**
- Use httpOnly cookies for session management
- Never store passwords client-side
- Use secure session tokens with expiration

---

### 8. IP Address Logging Without Consent
**Location:** `server/app.ts:62-63`, `server/src/services/socket.service.ts:20-24`
**Severity:** MEDIUM
**CVSS Score:** 4.3

```typescript
const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
console.log('New GW Market connexion from : ' + ip + ' in ' + geoipLite.lookup(ip));
```

**Issue:** IP addresses and geolocation data are logged without user consent. This may violate:
- GDPR (EU)
- CCPA (California)
- Other privacy regulations

**Recommendation:**
- Add privacy policy disclosure
- Implement consent mechanism
- Anonymize or hash IP addresses
- Set data retention policies

---

### 9. Trust Proxy Without Validation
**Location:** `server/app.ts:37`
**Severity:** MEDIUM
**CVSS Score:** 5.0

```typescript
app.set('trust proxy', true);
```

**Issue:** Setting `trust proxy` to `true` without validation means any `X-Forwarded-For` header is trusted. Attackers can spoof their IP address by adding this header.

**Recommendation:**
```typescript
// Only trust specific proxy IPs
app.set('trust proxy', ['loopback', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']);
// Or use number for hop count
app.set('trust proxy', 1);
```

---

### 10. Insufficient Input Validation on Shop Data
**Location:** `server/src/services/shop.service.ts:52-65`
**Severity:** MEDIUM
**CVSS Score:** 5.5

```typescript
if (
  !Array.isArray(rawShop.items) ||
  rawShop.items.some((item) => typeof item === 'string') ||
  typeof rawShop.player !== 'string' ||
  (rawShop.uuid && typeof rawShop.uuid !== 'string')
) {
  // reject
}
```

**Issue:** While basic type checking exists, validation is insufficient:
- No maximum length checks (player name could be megabytes)
- No maximum item count limit (DoS via memory exhaustion)
- No sanitization of player name (potential stored XSS if displayed unsafely)
- No validation of item structure fields

**Recommendation:**
```typescript
const MAX_PLAYER_NAME = 32;
const MAX_ITEMS = 100;
const MAX_ITEM_NAME = 128;

if (rawShop.player.length > MAX_PLAYER_NAME ||
    rawShop.items.length > MAX_ITEMS ||
    rawShop.items.some(i => i.name?.length > MAX_ITEM_NAME)) {
  return reject('Shop data exceeds limits');
}
```

---

### 11. Hardcoded Development Settings
**Location:** `server/.env`
**Severity:** MEDIUM
**CVSS Score:** 4.0

```
development = "true"
serverPort = "3026"
```

**Issue:**
- `.env` file is committed to the repository
- Development mode may be accidentally enabled in production
- `dataPassword` referenced in code but not set (security feature disabled)

**Recommendation:**
- Add `.env` to `.gitignore`
- Use `.env.example` for templates
- Ensure `development` defaults to `false`
- Set proper secrets in production

---

### 12. Socket.io Without CORS Configuration
**Location:** `server/src/services/socket.service.ts:12`
**Severity:** MEDIUM
**CVSS Score:** 4.7

```typescript
this.io = new SocketServer(server);
```

**Issue:** Socket.io is initialized without explicit CORS configuration. Default behavior may allow connections from any origin.

**Recommendation:**
```typescript
this.io = new SocketServer(server, {
  cors: {
    origin: ['https://gwmarket.net', 'https://gw1.shop'],
    methods: ['GET', 'POST'],
    credentials: true
  }
});
```

---

## Low Severity Vulnerabilities

### 13. Information Disclosure via Console Logging
**Location:** Multiple files
**Severity:** LOW
**CVSS Score:** 3.1

**Issue:** Extensive console.log statements in production code may leak sensitive information:
- IP addresses
- Shop data
- Internal state information

**Recommendation:**
- Use a proper logging library (winston, pino)
- Implement log levels (debug, info, warn, error)
- Disable verbose logging in production

---

### 14. Unused Authentication Code (Dead Code)
**Location:** `client/src/app/helpers/role.guard.ts`
**Severity:** LOW
**CVSS Score:** 2.5

```typescript
import { AuthService } from '../services/auth.service';  // File doesn't exist!
```

**Issue:** RoleGuard references a non-existent AuthService. This dead code:
- Creates confusion about security posture
- May lead to false sense of security
- Could cause runtime errors if route guards are activated

**Recommendation:**
- Remove unused authentication code
- Or implement proper authentication if needed

---

### 15. Potential Memory Leak in Shop Management
**Location:** `server/src/services/shop.service.ts:85-86`
**Severity:** LOW
**CVSS Score:** 3.5

```typescript
const shopToSave = this.allShopMap[shop.uuid] ? { ...this.allShopMap[shop.uuid], ...shop } : shop;
this.allShopMap[shop.uuid] = shopToSave;
```

**Issue:** Shops are stored indefinitely in memory with no cleanup mechanism. Over time, this could:
- Cause memory exhaustion
- Enable attackers to fill memory with fake shops

**Recommendation:**
- Implement shop expiration and cleanup
- Add maximum shop count limits
- Use persistent storage instead of in-memory maps

---

### 16. Debug Endpoint in Production
**Location:** `server/package.json:8`
**Severity:** LOW
**CVSS Score:** 2.3

```json
"debug": "nodemon --exec \"node --inspect-brk=0.0.0.0:9229 --require ts-node/register app.ts\""
```

**Issue:** Debug script binds to all interfaces (0.0.0.0), potentially exposing debugger port if accidentally run in production.

**Recommendation:**
- Bind debugger to localhost only: `--inspect-brk=127.0.0.1:9229`
- Never run debug scripts in production

---

## Additional Security Observations

### Positive Security Practices Found
1. **Field Sanitization**: Shop service rebuilds shop object to prevent field injection (`shop.service.ts:72-77`)
2. **UUID Generation**: Uses cryptographically sound nanoid for shop identifiers
3. **Basic Type Checking**: Input validation exists for shop data
4. **No innerHTML Usage**: Angular templates don't use dangerous innerHTML bindings
5. **HTTPS in Production**: Production environment uses HTTPS (`gw1.shop`)

### Missing Security Features
1. **No CSRF Protection**: No CSRF tokens implemented
2. **No Input Sanitization Library**: No DOMPurify or similar for user content
3. **No Audit Logging**: No logging of security-relevant events
4. **No Dependency Scanning**: No automated vulnerability scanning (npm audit)
5. **No Security.txt**: No security contact information

---

## Dependency Analysis

### Server Dependencies (Potential Concerns)
| Package | Version | Notes |
|---------|---------|-------|
| express | 4.18.2 | Review for updates |
| socket.io | 4.6.1 | Review for updates |
| mongodb | 5.3.0 | Not actively used in this version |
| geoip-lite | 1.4.7 | Privacy implications |

### Recommended Actions
```bash
# Run dependency audit
cd server && npm audit
cd client && npm audit

# Update dependencies
npm update
```

---

## Remediation Priority

### Immediate (Before Production)
1. Fix path traversal vulnerability (Critical #1)
2. Implement authentication for socket operations (Critical #2)
3. Add rate limiting (High #3)
4. Configure security headers (High #6)

### Short-term (Within 30 days)
5. Validate imported JSON files (High #4)
6. Remove client redirect vulnerability (High #5)
7. Secure sensitive data storage (Medium #7)
8. Configure CORS properly (Medium #12)

### Medium-term (Within 90 days)
9. Address privacy concerns (Medium #8)
10. Strengthen input validation (Medium #10)
11. Fix trust proxy configuration (Medium #9)
12. Clean up dead code (Low #14)

---

## Conclusion

The GW-Market application has several critical security vulnerabilities that require immediate attention, particularly the **path traversal** and **authentication bypass** issues. While the codebase shows some security awareness, implementing the recommendations in this review will significantly improve the application's security posture.

For an open-source marketplace handling user data and potentially valuable virtual items, security should be a top priority before public deployment.

---

*This security review was conducted through static code analysis. Dynamic testing and penetration testing are recommended for a complete security assessment.*
