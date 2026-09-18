const assert = require('node:assert');
const http = require('node:http');
const app = require('../src/server');
const dbHelpers = require('../src/db');
const { getSystemNetworkInfo } = require('../src/networkVerifier');

let server;
let baseUrl;

function request(method, path, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const reqHeaders = { ...headers };
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

async function runTests() {
  console.log('=== Starting Real-World Office Attendance Tests ===');

  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  baseUrl = `http://127.0.0.1:${port}`;
  console.log(`Test server running on ${baseUrl}`);

  try {
    // Test 1: Clean network state initially (no networks authorized)
    dbHelpers.clearAllNetworks();
    const netRes = await request('GET', '/api/network/status');
    assert.strictEqual(netRes.status, 200);
    assert.strictEqual(netRes.body.network.isAuthorized, false);
    console.log('✓ Initial state: Unconfigured network is blocked as expected');

    // Test 2: Login as Admin
    const adminLogin = await request('POST', '/api/auth/login', {
      body: { email: 'admin@office.local', pin: '1234' }
    });
    assert.strictEqual(adminLogin.status, 200);
    const adminToken = adminLogin.body.token;
    console.log('✓ Admin login successful');

    // Test 3: Admin sets current network as Office Wi-Fi via 1-click endpoint
    const setWifiRes = await request('POST', '/api/admin/networks/set-current', {
      headers: { Authorization: `Bearer ${adminToken}` },
      body: { mode: 'both' }
    });
    assert.strictEqual(setWifiRes.status, 200);
    assert.strictEqual(setWifiRes.body.success, true);
    assert.ok(setWifiRes.body.networks.length > 0);
    console.log('✓ Admin successfully set and authorized current Office Wi-Fi:', setWifiRes.body.networks.map(n => n.ip_or_cidr));

    // Test 4: Network status is now authorized for office Wi-Fi
    const netResAfter = await request('GET', '/api/network/status');
    assert.strictEqual(netResAfter.body.network.isAuthorized, true);
    console.log('✓ Device on Office Wi-Fi is now authorized');

    // Test 5: Login as employee Ven
    const loginVenRes = await request('POST', '/api/auth/login', {
      body: { email: 'ven@office.local', pin: '1234' }
    });
    assert.strictEqual(loginVenRes.status, 200);
    const venToken = loginVenRes.body.token;
    console.log('✓ Employee Ven logged in');

    // Test 6: Verify genuine metrics before attendance (0 present, 0 in office, 1 absent)
    const dashBefore = await request('GET', '/api/admin/dashboard', {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(dashBefore.status, 200);
    assert.strictEqual(dashBefore.body.summary.presentCount, 0);
    assert.strictEqual(dashBefore.body.summary.inOfficeCount, 0);
    assert.strictEqual(dashBefore.body.summary.absentCount, 1);
    console.log('✓ Genuine real metrics before check-in:', dashBefore.body.summary);

    // Test 7: Employee Check-In
    const checkInRes = await request('POST', '/api/attendance/check-in', {
      headers: { Authorization: `Bearer ${venToken}` }
    });
    assert.strictEqual(checkInRes.status, 200);
    assert.strictEqual(checkInRes.body.success, true);
    assert.ok(checkInRes.body.attendance.check_in_time);
    console.log('✓ Ven checked in at:', checkInRes.body.attendance.check_in_time);

    // Test 8: Verify genuine metrics during in-office (0 present, 1 in office, 0 absent)
    const dashDuring = await request('GET', '/api/admin/dashboard', {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(dashDuring.body.summary.inOfficeCount, 1);
    assert.strictEqual(dashDuring.body.summary.absentCount, 0);
    console.log('✓ Genuine real metrics during in-office:', dashDuring.body.summary);

    // Test 9: Employee Check-Out
    const checkOutRes = await request('POST', '/api/attendance/check-out', {
      headers: { Authorization: `Bearer ${venToken}` }
    });
    assert.strictEqual(checkOutRes.status, 200);
    assert.strictEqual(checkOutRes.body.success, true);
    assert.ok(checkOutRes.body.attendance.check_out_time);
    console.log('✓ Ven checked out at:', checkOutRes.body.attendance.check_out_time);

    // Test 10: Verify genuine metrics after checkout (1 present, 0 in office, 0 absent)
    const dashAfter = await request('GET', '/api/admin/dashboard', {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(dashAfter.body.summary.presentCount, 1);
    assert.strictEqual(dashAfter.body.summary.inOfficeCount, 0);
    assert.strictEqual(dashAfter.body.summary.absentCount, 0);
    console.log('✓ Genuine real metrics after checkout:', dashAfter.body.summary);

    // Test 11: Outside Network / Hotspot rejection
    // Simulate an external unauthorized client IP (e.g. 157.50.157.169)
    const extCheckIn = await request('POST', '/api/attendance/check-in', {
      headers: {
        Authorization: `Bearer ${venToken}`,
        'x-forwarded-for': '157.50.157.169'
      }
    });
    assert.strictEqual(extCheckIn.status, 403);
    assert.strictEqual(extCheckIn.body.error, 'You must be connected to the office Wi-Fi to mark attendance.');
    console.log('✓ Blocked unauthorized hotspot IP with exact message: "You must be connected to the office Wi-Fi to mark attendance."');

    // Test 12: Admin CSV Export
    const csvRes = await request('GET', '/api/admin/export-csv', {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    assert.strictEqual(csvRes.status, 200);
    assert.ok(csvRes.body.includes('Employee Code,Employee Name,Department'));
    console.log('✓ CSV export generated formatted real attendance data');

    console.log('\n=================================================');
    console.log('ALL REAL-WORLD ATTENDANCE TESTS PASSED (100%)!');
    console.log('=================================================\n');
  } finally {
    server.close();
  }
}

runTests().catch(err => {
  console.error('Test error:', err);
  if (server) server.close();
  process.exit(1);
});
