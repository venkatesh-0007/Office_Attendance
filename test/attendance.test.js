const assert = require('node:assert');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

// Configure isolated test database
const testDbPath = path.join(__dirname, 'test-isolated.db');
if (fs.existsSync(testDbPath)) {
  try { fs.unlinkSync(testDbPath); } catch (e) {}
}
process.env.NODE_ENV = 'test';
process.env.DB_PATH = testDbPath;

const app = require('../src/server');
const dbHelpers = require('../src/db');

let server;
let baseUrl;

// Helper to make HTTP requests with automatic cookie jar support
function createSessionClient() {
  let sessionCookie = '';

  async function request(method, reqPath, { headers = {}, body = null } = {}) {
    return new Promise((resolve, reject) => {
      const url = new URL(reqPath, baseUrl);
      const reqHeaders = { ...headers };

      if (sessionCookie) {
        reqHeaders['Cookie'] = sessionCookie;
      }

      let postData = null;
      if (body) {
        postData = JSON.stringify(body);
        reqHeaders['Content-Type'] = 'application/json';
        reqHeaders['Content-Length'] = Buffer.byteLength(postData);
      }

      const options = {
        method,
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        headers: reqHeaders
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          // Track set-cookie
          const setCookie = res.headers['set-cookie'];
          if (setCookie) {
            const rawCookie = Array.isArray(setCookie) ? setCookie[0] : setCookie;
            const cookiePart = rawCookie.split(';')[0];
            if (rawCookie.includes('session_token=;') || rawCookie.includes('Max-Age=0')) {
              sessionCookie = '';
            } else if (cookiePart.startsWith('session_token=')) {
              sessionCookie = cookiePart;
            }
          }

          let json = null;
          try {
            json = JSON.parse(data);
          } catch (e) {
            json = data;
          }

          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: json
          });
        });
      });

      req.on('error', reject);
      if (postData) req.write(postData);
      req.end();
    });
  }

  return {
    request,
    getCookie: () => sessionCookie,
    setCookie: (c) => { sessionCookie = c; },
    clearCookie: () => { sessionCookie = ''; }
  };
}

async function runTests() {
  console.log('===========================================================');
  console.log('STARTING HARDENED OFFICE ATTENDANCE TEST SUITE (ISOLATED DB)');
  console.log('===========================================================\n');

  dbHelpers.reloadDb();

  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;
  console.log(`✓ Test server running on ${baseUrl}`);
  console.log(`✓ Using isolated test DB: ${testDbPath}\n`);

  try {
    const adminClient = createSessionClient();
    const venClient = createSessionClient();
    const anonymousClient = createSessionClient();

    // -------------------------------------------------------------
    // Test 1: Clean Initial Network State
    // -------------------------------------------------------------
    console.log('--- Test 1: Clean Initial Network State ---');
    await dbHelpers.clearAllNetworks();
    const initialStatus = await anonymousClient.request('GET', '/api/network/status');
    assert.strictEqual(initialStatus.status, 200);
    assert.strictEqual(initialStatus.body.network.isAuthorized, false);
    console.log('✓ Initial state: Unconfigured office network is blocked (isAuthorized = false)');

    // -------------------------------------------------------------
    // Test 2: Login Rate Limiter & Lockout (Problem 7)
    // -------------------------------------------------------------
    console.log('\n--- Test 2: Brute-Force Rate Limiting & Lockout ---');
    const attackerClient = createSessionClient();
    let lockoutHit = false;
    for (let i = 1; i <= 6; i++) {
      const failRes = await attackerClient.request('POST', '/api/auth/login', {
        body: { email: 'admin@office.local', pin: 'wrong-pin' }
      });
      if (failRes.status === 429) {
        lockoutHit = true;
        assert.ok(failRes.body.error.includes('Too many failed login attempts'));
        console.log(`✓ Lockout triggered at attempt #${i}: 429 Too Many Requests`);
        break;
      }
    }
    assert.strictEqual(lockoutHit, true, 'Expected rate limiter to trigger 429 after 5 failed attempts');

    // -------------------------------------------------------------
    // Test 3: Admin Login & Mandatory Initial PIN Change (Problem 6)
    // -------------------------------------------------------------
    console.log('\n--- Test 3: Default Credentials & Forced PIN Change ---');
    // Login with a different client IP (test client) to bypass lockout from attacker simulation
    const adminLoginRes = await adminClient.request('POST', '/api/auth/login', {
      headers: { 'x-test-ip': '10.0.99.1' },
      body: { email: 'admin@office.local', pin: '1234' }
    });
    assert.strictEqual(adminLoginRes.status, 200);
    assert.strictEqual(adminLoginRes.body.user.must_change_pin, true);
    assert.strictEqual(adminLoginRes.body.token, undefined, 'Session token must NOT be returned in JSON');
    assert.ok(adminClient.getCookie().includes('session_token='), 'HttpOnly cookie must be set in header');
    console.log('✓ Admin login successful with must_change_pin: true and cookie-only auth');

    // Attempting admin operation before changing PIN must be rejected
    const blockedAdminOp = await adminClient.request('GET', '/api/admin/dashboard');
    assert.strictEqual(blockedAdminOp.status, 403);
    assert.strictEqual(blockedAdminOp.body.code, 'MUST_CHANGE_PIN');
    console.log('✓ Blocked access to admin functions before changing default PIN (403 MUST_CHANGE_PIN)');

    // Attempting to change PIN to another weak default must be rejected
    const weakPinRes = await adminClient.request('POST', '/api/auth/change-pin', {
      body: { newPin: '1234' }
    });
    assert.strictEqual(weakPinRes.status, 400);
    console.log('✓ Rejected weak PIN change to "1234"');

    // Successfully change PIN to secure PIN
    const updatePinRes = await adminClient.request('POST', '/api/auth/change-pin', {
      body: { newPin: 'AdminSecurePass890' }
    });
    assert.strictEqual(updatePinRes.status, 200);
    console.log('✓ Admin successfully changed PIN to strong credential');

    // -------------------------------------------------------------
    // Test 4: Office Wi-Fi Setup with Explicit Confirmation (Problem 10)
    // -------------------------------------------------------------
    console.log('\n--- Test 4: Office Wi-Fi Setup with Confirmation ---');
    const OFFICE_PUBLIC_IP = '103.140.155.116';

    // Unconfirmed request rejected
    const unconfirmedRes = await adminClient.request('POST', '/api/admin/networks/set-current', {
      body: { confirmed: false }
    });
    assert.strictEqual(unconfirmedRes.status, 400);
    console.log('✓ Unconfirmed network setup rejected (confirmation required)');

    // Add specific office public IP
    const addNetRes = await adminClient.request('POST', '/api/admin/networks', {
      headers: { 'x-test-ip': '10.0.99.1' },
      body: {
        name: 'Headquarters Fiber Wi-Fi',
        ip_or_cidr: OFFICE_PUBLIC_IP,
        description: 'Primary Office Public Gateway'
      }
    });
    assert.strictEqual(addNetRes.status, 200);
    console.log(`✓ Authorized Office Wi-Fi public IP: ${OFFICE_PUBLIC_IP}`);

    // Verify broad network rejection
    const broadNetRes = await adminClient.request('POST', '/api/admin/networks', {
      headers: { 'x-test-ip': '10.0.99.1' },
      body: {
        name: 'Insecure Broad Subnet',
        ip_or_cidr: '192.168.0.0/16'
      }
    });
    assert.strictEqual(broadNetRes.status, 400);
    console.log('✓ Broad network 192.168.0.0/16 strictly blocked from configuration');

    // -------------------------------------------------------------
    // Test 5: Employee Login & Mandatory PIN Change
    // -------------------------------------------------------------
    console.log('\n--- Test 5: Employee Login & PIN Change ---');
    const venLoginRes = await venClient.request('POST', '/api/auth/login', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP },
      body: { email: 'ven@office.local', pin: '1234' }
    });
    assert.strictEqual(venLoginRes.status, 200);
    assert.strictEqual(venLoginRes.body.user.must_change_pin, true);

    const venPinUpdate = await venClient.request('POST', '/api/auth/change-pin', {
      body: { newPin: 'VenSecret7788' }
    });
    assert.strictEqual(venPinUpdate.status, 200);
    console.log('✓ Employee Ven logged in and successfully updated PIN');

    // -------------------------------------------------------------
    // Test 6: THE 3-NETWORK VERIFICATION TEST (Problem 16)
    // -------------------------------------------------------------
    console.log('\n--- Test 6: Mandatory 3-Network Attendance Testing ---');

    // 6A: Home Wi-Fi -> MUST BE REJECTED
    console.log('Testing Home Wi-Fi rejection...');
    const homeWifiRes = await venClient.request('POST', '/api/attendance/check-in', {
      headers: { 'x-test-ip': '198.51.100.24' } // Home residential IP
    });
    assert.strictEqual(homeWifiRes.status, 403);
    assert.strictEqual(homeWifiRes.body.code, 'NETWORK_NOT_AUTHORIZED');
    assert.strictEqual(homeWifiRes.body.error, 'You must be connected to the office Wi-Fi to mark attendance.');
    console.log('✓ Home Wi-Fi (198.51.100.24) -> "I\'m in Office" -> ✗ STRICTLY REJECTED (403)');

    // 6B: Mobile 4G/5G Hotspot -> MUST BE REJECTED
    console.log('Testing Mobile 4G/5G Hotspot rejection...');
    const mobileDataRes = await venClient.request('POST', '/api/attendance/check-in', {
      headers: { 'x-test-ip': '157.50.157.169' } // Mobile cellular IP
    });
    assert.strictEqual(mobileDataRes.status, 403);
    assert.strictEqual(mobileDataRes.body.code, 'NETWORK_NOT_AUTHORIZED');
    assert.strictEqual(mobileDataRes.body.error, 'You must be connected to the office Wi-Fi to mark attendance.');
    console.log('✓ Mobile 4G/5G (157.50.157.169) -> "I\'m in Office" -> ✗ STRICTLY REJECTED (403)');

    // 6C: Office Wi-Fi -> MUST WORK
    console.log('Testing Office Wi-Fi approval...');
    const officeWifiRes = await venClient.request('POST', '/api/attendance/check-in', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP } // Office authorized IP
    });
    assert.strictEqual(officeWifiRes.status, 200);
    assert.strictEqual(officeWifiRes.body.success, true);
    assert.ok(officeWifiRes.body.attendance.check_in_time);
    console.log(`✓ Office Wi-Fi (${OFFICE_PUBLIC_IP}) -> "I\'m in Office" -> ✓ MUST WORK (200 OK)`);
    console.log(`  Recorded timestamp: ${officeWifiRes.body.attendance.check_in_time}`);

    // -------------------------------------------------------------
    // Test 7: Double-Click / Duplicate Check-in Prevention (Problem 4)
    // -------------------------------------------------------------
    console.log('\n--- Test 7: Double-Click Concurrency Guard ---');
    const doubleClickRes = await venClient.request('POST', '/api/attendance/check-in', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP }
    });
    assert.strictEqual(doubleClickRes.status, 400);
    assert.strictEqual(doubleClickRes.body.code, 'ALREADY_CHECKED_IN');
    console.log('✓ Double-click second check-in attempt -> ✗ REJECTED (400 ALREADY_CHECKED_IN)');

    // -------------------------------------------------------------
    // Test 8: Page Refresh / Session Persistence
    // -------------------------------------------------------------
    console.log('\n--- Test 8: Page Refresh State Persistence ---');
    const refreshRes = await venClient.request('GET', '/api/attendance/today', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP }
    });
    assert.strictEqual(refreshRes.status, 200);
    assert.strictEqual(refreshRes.body.attendance.id, officeWifiRes.body.attendance.id);
    assert.strictEqual(refreshRes.body.attendance.check_in_time, officeWifiRes.body.attendance.check_in_time);
    console.log('✓ Page refresh -> Attendance status remains identical');

    // -------------------------------------------------------------
    // Test 9: Logout and Login Persistence
    // -------------------------------------------------------------
    console.log('\n--- Test 9: Logout / Login Persistence ---');
    await venClient.request('POST', '/api/auth/logout');
    assert.strictEqual(venClient.getCookie(), '', 'Session cookie should be cleared after logout');

    // Log back in with the new PIN
    const reLoginRes = await venClient.request('POST', '/api/auth/login', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP },
      body: { email: 'ven@office.local', pin: 'VenSecret7788' }
    });
    assert.strictEqual(reLoginRes.status, 200);

    const reLoginStatus = await venClient.request('GET', '/api/attendance/today', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP }
    });
    assert.strictEqual(reLoginStatus.status, 200);
    assert.strictEqual(reLoginStatus.body.attendance.check_in_time, officeWifiRes.body.attendance.check_in_time);
    console.log('✓ Logout and re-login -> Attendance status retained');

    // -------------------------------------------------------------
    // Test 10: Multi-Device (Laptop -> Phone)
    // -------------------------------------------------------------
    console.log('\n--- Test 10: Multi-Device Consistency (Laptop -> Phone) ---');
    const phoneClient = createSessionClient();
    const phoneLogin = await phoneClient.request('POST', '/api/auth/login', {
      headers: {
        'x-test-ip': OFFICE_PUBLIC_IP,
        'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'
      },
      body: { email: 'ven@office.local', pin: 'VenSecret7788' }
    });
    assert.strictEqual(phoneLogin.status, 200);

    const phoneAttendance = await phoneClient.request('GET', '/api/attendance/today', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP }
    });
    assert.strictEqual(phoneAttendance.status, 200);
    assert.strictEqual(phoneAttendance.body.attendance.id, officeWifiRes.body.attendance.id);
    console.log('✓ Laptop -> Phone: Same employee sees identical checked-in status across devices');

    // -------------------------------------------------------------
    // Test 11: Check-out Edge Cases
    // -------------------------------------------------------------
    console.log('\n--- Test 11: Check-out Flow & Double Checkout Guard ---');
    // First checkout -> Success
    const checkOutRes1 = await venClient.request('POST', '/api/attendance/check-out', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP }
    });
    assert.strictEqual(checkOutRes1.status, 200);
    assert.strictEqual(checkOutRes1.body.success, true);
    assert.ok(checkOutRes1.body.attendance.check_out_time);
    console.log(`✓ First checkout -> Success at ${checkOutRes1.body.attendance.check_out_time}`);

    // Second checkout -> Rejected
    const checkOutRes2 = await venClient.request('POST', '/api/attendance/check-out', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP }
    });
    assert.strictEqual(checkOutRes2.status, 400);
    assert.strictEqual(checkOutRes2.body.code, 'ALREADY_CHECKED_OUT');
    console.log('✓ Second checkout attempt -> ✗ REJECTED (400 ALREADY_CHECKED_OUT)');

    // Check out first (before checking in) -> Rejected
    console.log('\n--- Test 12: Checkout Before Check-in Guard ---');
    // Create new employee Sarah
    await adminClient.request('POST', '/api/admin/employees', {
      body: {
        name: 'Sarah Connor',
        email: 'sarah@office.local',
        department: 'Operations',
        role: 'employee',
        pin: 'SarahSecure99'
      }
    });

    const sarahClient = createSessionClient();
    await sarahClient.request('POST', '/api/auth/login', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP },
      body: { email: 'sarah@office.local', pin: 'SarahSecure99' }
    });

    // Sarah changes initial PIN
    await sarahClient.request('POST', '/api/auth/change-pin', {
      body: { newPin: 'SarahPersonal8899' }
    });

    const checkOutFirstRes = await sarahClient.request('POST', '/api/attendance/check-out', {
      headers: { 'x-test-ip': OFFICE_PUBLIC_IP }
    });
    assert.strictEqual(checkOutFirstRes.status, 400);
    assert.strictEqual(checkOutFirstRes.body.code, 'NOT_CHECKED_IN');
    console.log('✓ Checkout before check-in -> ✗ REJECTED (400 NOT_CHECKED_IN)');

    // -------------------------------------------------------------
    // Test 13: Audit Trail Verification (Problem 11)
    // -------------------------------------------------------------
    console.log('\n--- Test 13: Audit Trail Verification ---');
    const auditRes = await adminClient.request('GET', '/api/admin/audit-logs');
    assert.strictEqual(auditRes.status, 200);
    assert.ok(auditRes.body.logs.length > 0);

    const actionTypes = auditRes.body.logs.map(l => l.action);
    console.log('✓ Audit log recorded actions:', [...new Set(actionTypes)]);
    assert.ok(actionTypes.includes('LOGIN_SUCCESS'));
    assert.ok(actionTypes.includes('PIN_CHANGED'));
    assert.ok(actionTypes.includes('ATTENDANCE_CHECK_IN'));
    assert.ok(actionTypes.includes('ATTENDANCE_CHECK_OUT'));
    assert.ok(actionTypes.includes('NETWORK_ADDED'));
    assert.ok(actionTypes.includes('EMPLOYEE_CREATED'));
    console.log('✓ Immutable audit trail contains all expected security and operational events');

    console.log('\n===========================================================');
    console.log('ALL 13 TESTS PASSED (100%) WITH ZERO DATA POLLUTION');
    console.log('===========================================================\n');
  } finally {
    if (server) server.close();
    // Clean up isolated test database
    try {
      if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
      const wal = `${testDbPath}-wal`;
      const shm = `${testDbPath}-shm`;
      if (fs.existsSync(wal)) fs.unlinkSync(wal);
      if (fs.existsSync(shm)) fs.unlinkSync(shm);
      console.log(`✓ Cleaned up isolated test database: ${testDbPath}`);
    } catch (e) {
      console.warn('Cleanup warning:', e.message);
    }
  }
}

runTests().catch(err => {
  console.error('\n❌ Test failure:', err);
  if (server) server.close();
  try {
    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
  } catch (e) {}
  process.exit(1);
});
