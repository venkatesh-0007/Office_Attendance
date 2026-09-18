const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('node:path');
const ipaddr = require('ipaddr.js');

const dbHelpers = require('./db');
const {
  verifyRequestNetwork,
  getSystemNetworkInfo,
  invalidatePublicIpCache,
  getClientIp,
  normalizeIp
} = require('./networkVerifier');
const { authenticate, requireAuth, requireAdmin } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable JSON body parsing & cookie parsing
app.use(express.json());
app.use(cookieParser());

// Trust proxy for reverse proxy setups (Vercel, Cloudflare, AWS ALB)
app.set('trust proxy', 1);

// Auth middleware for all routes
app.use(authenticate);

// Security (Problem 6): Force PIN Change guard for default credentials
app.use((req, res, next) => {
  if (req.user && req.user.must_change_pin && 
      !req.path.startsWith('/api/auth/') && 
      req.path !== '/api/network/status' &&
      !req.path.startsWith('/css/') && 
      !req.path.startsWith('/js/') && 
      req.path !== '/') {
    return res.status(403).json({
      error: 'Default PIN in use. You must change your PIN before accessing attendance functions.',
      code: 'MUST_CHANGE_PIN'
    });
  }
  next();
});

// -------------------------------------------------------------
// Security: In-Memory Login Rate Limiter & Lockout (Problem 7)
// -------------------------------------------------------------
const failedLoginTracker = new Map();
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes lockout

function checkLoginRateLimit(key) {
  const record = failedLoginTracker.get(key);
  if (!record) return { isLocked: false };

  const now = Date.now();
  if (record.lockUntil && record.lockUntil > now) {
    const remainingMinutes = Math.ceil((record.lockUntil - now) / 60000);
    return { isLocked: true, remainingMinutes };
  }

  // Lockout expired, reset
  if (record.lockUntil && record.lockUntil <= now) {
    failedLoginTracker.delete(key);
    return { isLocked: false };
  }

  return { isLocked: false };
}

function recordFailedLogin(key) {
  const now = Date.now();
  const record = failedLoginTracker.get(key) || { count: 0, firstAttempt: now };

  record.count += 1;
  if (record.count >= MAX_FAILED_ATTEMPTS) {
    record.lockUntil = now + LOCKOUT_DURATION_MS;
  }
  failedLoginTracker.set(key, record);
}

function clearFailedLogin(key) {
  failedLoginTracker.delete(key);
}

// -------------------------------------------------------------
// Helpers: Duration & Formatting
// -------------------------------------------------------------
function formatDuration(ms) {
  if (ms == null || isNaN(ms) || ms < 0) return '—';
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (hours === 0 && minutes === 0) return '< 1m';
  if (hours === 0) return `${minutes}m`;
  return `${hours}h ${String(minutes).padStart(2, '0')}m`;
}

function formatTime(isoString, includeSeconds = false) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    let hours = d.getHours();
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const seconds = String(d.getSeconds()).padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12;
    const hoursStr = String(hours).padStart(2, '0');
    return includeSeconds ? `${hoursStr}:${minutes}:${seconds} ${ampm}` : `${hoursStr}:${minutes} ${ampm}`;
  } catch (e) {
    return '—';
  }
}

// -------------------------------------------------------------
// API Routes
// -------------------------------------------------------------

// Network status check (Informational only for UI indicator)
app.get('/api/network/status', async (req, res) => {
  try {
    const netStatus = await verifyRequestNetwork(req);
    res.json({
      status: 'ok',
      network: netStatus,
      disclaimer: 'Office Network Verification verifies connection to authorized office Wi-Fi networks.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to verify network status.' });
  }
});

// Authentication: Login with Rate Limiting & HttpOnly Cookie Only
app.post('/api/auth/login', async (req, res) => {
  const { email, pin } = req.body;
  const clientIp = getClientIp(req);

  if (!email || !pin) {
    return res.status(400).json({ error: 'Work email and PIN/Password are required.' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const rateLimitKey = `${clientIp}_${cleanEmail}`;

  // Check brute-force lockout
  const { isLocked, remainingMinutes } = checkLoginRateLimit(rateLimitKey);
  if (isLocked) {
    return res.status(429).json({
      error: `Too many failed login attempts. Account temporarily locked. Please try again in ${remainingMinutes} minute(s).`
    });
  }

  const employee = await dbHelpers.getEmployeeByEmail(cleanEmail);
  if (!employee) {
    recordFailedLogin(rateLimitKey);
    await dbHelpers.addAuditLog({
      action: 'LOGIN_FAILED',
      details: `Failed login attempt for non-existent email: ${cleanEmail}`,
      ipAddress: clientIp
    });
    return res.status(401).json({ error: 'Invalid email or PIN.' });
  }

  const isValid = dbHelpers.verifyPin(String(pin).trim(), employee.pin_hash, employee.salt);
  if (!isValid) {
    recordFailedLogin(rateLimitKey);
    await dbHelpers.addAuditLog({
      userId: employee.id,
      userName: employee.name,
      action: 'LOGIN_FAILED',
      details: `Failed PIN attempt for user ${cleanEmail}`,
      ipAddress: clientIp
    });
    return res.status(401).json({ error: 'Invalid email or PIN.' });
  }

  // Clear rate limit record on successful login
  clearFailedLogin(rateLimitKey);

  const userAgent = req.headers['user-agent'] || '';
  // Role-based session duration: Admins 4h vs Employees 30d
  const { token, expiresAt, maxAgeMs } = await dbHelpers.createSession(employee.id, employee.role, userAgent);

  // Security (Problem 8): Strictly HttpOnly, SameSite cookie. Token is NOT returned in JSON response!
  res.cookie('session_token', token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: maxAgeMs,
    secure: process.env.NODE_ENV === 'production'
  });

  await dbHelpers.addAuditLog({
    userId: employee.id,
    userName: employee.name,
    action: 'LOGIN_SUCCESS',
    details: `User logged in (${employee.role})`,
    ipAddress: clientIp
  });

  res.json({
    message: 'Login successful',
    expiresAt,
    user: {
      id: employee.id,
      name: employee.name,
      email: employee.email,
      role: employee.role,
      department: employee.department,
      employee_code: employee.employee_code,
      must_change_pin: Boolean(employee.must_change_pin)
    }
  });
});

// Force PIN Change for default/initial credentials (Problem 6)
app.post('/api/auth/change-pin', requireAuth, async (req, res) => {
  const { newPin } = req.body;
  const clientIp = getClientIp(req);

  if (!newPin || String(newPin).trim().length < 4) {
    return res.status(400).json({ error: 'New PIN must be at least 4 characters long.' });
  }

  const trimmedPin = String(newPin).trim();
  if (trimmedPin === '1234' || trimmedPin === '0000' || trimmedPin === '1111') {
    return res.status(400).json({ error: 'Please choose a stronger PIN than the default common values.' });
  }

  try {
    await dbHelpers.updatePin(req.user.id, trimmedPin);
    await dbHelpers.addAuditLog({
      userId: req.user.id,
      userName: req.user.name,
      action: 'PIN_CHANGED',
      details: 'User updated their security PIN',
      ipAddress: clientIp
    });

    res.json({ success: true, message: 'PIN updated successfully. Your account is now secured.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update PIN.' });
  }
});

// Authentication: Current User
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Authentication: Logout
app.post('/api/auth/logout', async (req, res) => {
  const clientIp = getClientIp(req);
  if (req.user?.token) {
    await dbHelpers.deleteSession(req.user.token);
    await dbHelpers.addAuditLog({
      userId: req.user.id,
      userName: req.user.name,
      action: 'LOGOUT',
      details: 'User logged out',
      ipAddress: clientIp
    });
  }
  res.clearCookie('session_token');
  res.json({ success: true, message: 'Logged out successfully' });
});

// -------------------------------------------------------------
// Employee Attendance Endpoints
// -------------------------------------------------------------

// Today's attendance status for logged-in employee
app.get('/api/attendance/today', requireAuth, async (req, res) => {
  const todayDate = dbHelpers.getLocalDateString();
  const attendance = await dbHelpers.getTodayAttendance(req.user.id, todayDate);
  const netStatus = await verifyRequestNetwork(req);

  let formatted = null;
  if (attendance) {
    let durationMs = null;
    if (attendance.check_in_time && attendance.check_out_time) {
      durationMs = new Date(attendance.check_out_time) - new Date(attendance.check_in_time);
    } else if (attendance.check_in_time) {
      durationMs = new Date() - new Date(attendance.check_in_time);
    }

    formatted = {
      ...attendance,
      check_in_formatted: formatTime(attendance.check_in_time, true),
      check_out_formatted: formatTime(attendance.check_out_time, true),
      duration_text: formatDuration(durationMs),
      duration_ms: durationMs
    };
  }

  res.json({
    date: todayDate,
    server_time: new Date().toISOString(),
    attendance: formatted,
    network: netStatus
  });
});

// Employee Check-In (Strict backend network verification & atomic duplicate prevention)
app.post('/api/attendance/check-in', requireAuth, async (req, res) => {
  const netStatus = await verifyRequestNetwork(req);
  if (!netStatus.isAuthorized) {
    return res.status(403).json({
      error: 'You must be connected to the office Wi-Fi to mark attendance.',
      code: 'NETWORK_NOT_AUTHORIZED',
      network: netStatus
    });
  }

  const now = new Date();
  const todayDate = dbHelpers.getLocalDateString(now);

  // Check if already checked in today
  const existing = await dbHelpers.getTodayAttendance(req.user.id, todayDate);
  if (existing) {
    return res.status(400).json({
      error: 'You have already checked in for today.',
      code: 'ALREADY_CHECKED_IN',
      attendance: existing
    });
  }

  // Late arrival check: after 09:30 AM local time
  const currentHours = now.getHours();
  const currentMins = now.getMinutes();
  const isLate = currentHours > 9 || (currentHours === 9 && currentMins > 30);

  const verificationMethod = `office_wifi_ip:${netStatus.clientIp}`;
  const checkInIso = now.toISOString();

  try {
    const record = await dbHelpers.recordCheckIn({
      employeeId: req.user.id,
      name: req.user.name,
      dateStr: todayDate,
      checkInIso,
      verificationMethod,
      isLate
    });

    await dbHelpers.addAuditLog({
      userId: req.user.id,
      userName: req.user.name,
      action: 'ATTENDANCE_CHECK_IN',
      details: `Checked in on ${todayDate} (${isLate ? 'Late' : 'On Time'}) via ${verificationMethod}`,
      ipAddress: netStatus.clientIp
    });

    res.json({
      success: true,
      message: 'Checked in successfully! Have a productive day.',
      attendance: {
        ...record,
        check_in_formatted: formatTime(record.check_in_time, true),
        check_out_formatted: '—',
        duration_text: '0m'
      }
    });
  } catch (err) {
    if (err.message?.includes('UNIQUE constraint') || err.code === 6 || err.message?.includes('already exists')) {
      return res.status(400).json({
        error: 'You have already checked in for today.',
        code: 'ALREADY_CHECKED_IN'
      });
    }
    console.error('Error recording check-in:', err);
    res.status(500).json({ error: 'Failed to record attendance. Please try again.' });
  }
});

// Employee Check-Out
app.post('/api/attendance/check-out', requireAuth, async (req, res) => {
  const netStatus = await verifyRequestNetwork(req);
  if (!netStatus.isAuthorized) {
    return res.status(403).json({
      error: 'You must be connected to the office Wi-Fi to mark attendance.',
      code: 'NETWORK_NOT_AUTHORIZED',
      network: netStatus
    });
  }

  const now = new Date();
  const todayDate = dbHelpers.getLocalDateString(now);

  const existing = await dbHelpers.getTodayAttendance(req.user.id, todayDate);
  if (!existing) {
    return res.status(400).json({
      error: 'You have not checked in yet today.',
      code: 'NOT_CHECKED_IN'
    });
  }

  if (existing.check_out_time) {
    return res.status(400).json({
      error: 'You have already checked out for today.',
      code: 'ALREADY_CHECKED_OUT',
      attendance: existing
    });
  }

  const checkOutIso = now.toISOString();
  const durationMs = new Date(checkOutIso) - new Date(existing.check_in_time);
  const status = existing.status === 'late' ? 'late' : 'present';

  try {
    const updated = await dbHelpers.recordCheckOut({
      attendanceId: existing.id,
      checkOutIso,
      status
    });

    await dbHelpers.addAuditLog({
      userId: req.user.id,
      userName: req.user.name,
      action: 'ATTENDANCE_CHECK_OUT',
      details: `Checked out on ${todayDate}. Duration: ${formatDuration(durationMs)}`,
      ipAddress: netStatus.clientIp
    });

    res.json({
      success: true,
      message: 'Checked out successfully. Have a great evening!',
      attendance: {
        ...updated,
        check_in_formatted: formatTime(updated.check_in_time, true),
        check_out_formatted: formatTime(updated.check_out_time, true),
        duration_text: formatDuration(durationMs)
      }
    });
  } catch (err) {
    console.error('Error recording check-out:', err);
    res.status(500).json({ error: 'Failed to record check-out. Please try again.' });
  }
});

// Employee personal attendance history
app.get('/api/attendance/history', requireAuth, async (req, res) => {
  const history = await dbHelpers.getAttendanceHistory(req.user.id, 30);
  const formatted = history.map(item => {
    let durationMs = null;
    if (item.check_in_time && item.check_out_time) {
      durationMs = new Date(item.check_out_time) - new Date(item.check_in_time);
    }
    return {
      ...item,
      check_in_formatted: formatTime(item.check_in_time),
      check_out_formatted: formatTime(item.check_out_time),
      duration_text: formatDuration(durationMs)
    };
  });

  res.json({ history: formatted });
});

// -------------------------------------------------------------
// Admin Dashboard & Management Endpoints
// -------------------------------------------------------------

// Admin Dashboard Summary & Live Attendance Table
app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  const queryDate = req.query.date || dbHelpers.getLocalDateString();
  const rawRecords = await dbHelpers.getAttendanceByDate(queryDate);

  let presentCount = 0;
  let inOfficeCount = 0;
  let absentCount = 0;
  let lateCount = 0;

  const records = rawRecords.map(rec => {
    let durationMs = null;
    let displayStatus = 'Absent';

    if (!rec.attendance_id || !rec.check_in_time) {
      absentCount++;
      displayStatus = 'Absent';
    } else if (rec.check_in_time && !rec.check_out_time) {
      inOfficeCount++;
      displayStatus = rec.status === 'late' ? 'Late' : 'In Office';
      if (rec.status === 'late') lateCount++;
      durationMs = new Date() - new Date(rec.check_in_time);
    } else {
      presentCount++;
      displayStatus = rec.status === 'late' ? 'Late' : 'Present';
      if (rec.status === 'late') lateCount++;
      durationMs = new Date(rec.check_out_time) - new Date(rec.check_in_time);
    }

    return {
      employee_id: rec.employee_id,
      employee_code: rec.employee_code,
      name: rec.name,
      department: rec.department,
      email: rec.email,
      attendance_id: rec.attendance_id,
      date: rec.date || queryDate,
      check_in_time: rec.check_in_time,
      check_in_formatted: formatTime(rec.check_in_time),
      check_out_time: rec.check_out_time,
      check_out_formatted: formatTime(rec.check_out_time),
      duration_text: formatDuration(durationMs),
      duration_ms: durationMs,
      verification_method: rec.verification_method || '—',
      status: displayStatus,
      raw_status: rec.status
    };
  });

  const totalEmployees = rawRecords.length;

  res.json({
    date: queryDate,
    summary: {
      totalEmployees,
      presentCount,
      inOfficeCount,
      absentCount,
      lateCount
    },
    records
  });
});

// Admin: Export Attendance to CSV
app.get('/api/admin/export-csv', requireAdmin, async (req, res) => {
  const { startDate, endDate, date } = req.query;
  let records;

  if (date) {
    records = await dbHelpers.getAttendanceByDate(date);
  } else {
    records = await dbHelpers.getAllAttendanceRecords({ startDate, endDate });
  }

  const csvHeaders = [
    'Employee Code',
    'Employee Name',
    'Department',
    'Email',
    'Date',
    'Check In Time',
    'Check Out Time',
    'Working Duration',
    'Status',
    'Verification Method'
  ];

  const csvRows = records.map(r => {
    let durationMs = null;
    if (r.check_in_time && r.check_out_time) {
      durationMs = new Date(r.check_out_time) - new Date(r.check_in_time);
    }

    let statusDisplay = 'Absent';
    if (r.check_in_time && !r.check_out_time) {
      statusDisplay = r.status === 'late' ? 'Late' : 'In Office';
    } else if (r.check_in_time && r.check_out_time) {
      statusDisplay = r.status === 'late' ? 'Late' : 'Present';
    }

    return [
      `"${r.employee_code || ''}"`,
      `"${r.name || ''}"`,
      `"${r.department || ''}"`,
      `"${r.email || ''}"`,
      `"${r.date || date || ''}"`,
      `"${formatTime(r.check_in_time)}"`,
      `"${formatTime(r.check_out_time)}"`,
      `"${formatDuration(durationMs)}"`,
      `"${statusDisplay}"`,
      `"${r.verification_method || 'N/A'}"`
    ].join(',');
  });

  const csvContent = [csvHeaders.join(','), ...csvRows].join('\n');
  const filenameDate = date || startDate || dbHelpers.getLocalDateString();

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="attendance_report_${filenameDate}.csv"`);
  res.send(csvContent);
});

// Admin: Get Office Networks and System Environment
app.get('/api/admin/networks', requireAdmin, async (req, res) => {
  const networks = await dbHelpers.getAllNetworks();
  const systemInfo = await getSystemNetworkInfo();
  const currentNetStatus = await verifyRequestNetwork(req);

  res.json({
    networks,
    system_info: systemInfo,
    current_request: currentNetStatus
  });
});

// Admin: Controlled update of Office Wi-Fi with confirmation requirement (Problem 10)
app.post('/api/admin/networks/set-current', requireAdmin, async (req, res) => {
  const { confirmed = false, custom_name, replaceAll = false } = req.body;
  const clientIp = getClientIp(req);

  if (!confirmed) {
    return res.status(400).json({
      error: 'Confirmation required. Please review the detected IP before authorizing.'
    });
  }

  const systemInfo = await getSystemNetworkInfo();
  invalidatePublicIpCache();

  if (replaceAll) {
    await dbHelpers.clearAllNetworks();
  }

  const added = [];
  const targetIp = systemInfo.publicIp !== 'Unavailable' ? systemInfo.publicIp : systemInfo.primaryLocalIp;

  if (targetIp && targetIp !== 'Unavailable') {
    const net = await dbHelpers.addNetwork({
      name: custom_name || `Office Wi-Fi (${targetIp})`,
      ip_or_cidr: targetIp,
      description: 'Office Gateway IP'
    });
    added.push(net);
  }

  invalidatePublicIpCache();
  const currentNetStatus = await verifyRequestNetwork(req);

  await dbHelpers.addAuditLog({
    userId: req.user.id,
    userName: req.user.name,
    action: 'NETWORK_AUTHORIZED',
    details: `Authorized Office Wi-Fi IP: ${targetIp}`,
    ipAddress: clientIp
  });

  res.json({
    success: true,
    message: `Office network (${targetIp}) authorized successfully!`,
    networks: await dbHelpers.getAllNetworks(),
    current_request: currentNetStatus
  });
});

// Admin: Add specific Office IP or Subnet
app.post('/api/admin/networks', requireAdmin, async (req, res) => {
  const { name, ip_or_cidr, description } = req.body;
  const clientIp = getClientIp(req);

  if (!name || !ip_or_cidr) {
    return res.status(400).json({ error: 'Network name and IP / CIDR are required.' });
  }

  const cleanInput = ip_or_cidr.trim();

  // Strictly block loopback (Problem 2)
  if (cleanInput === '127.0.0.1' || cleanInput === '::1' || cleanInput === 'localhost') {
    return res.status(400).json({ error: 'Loopback address (127.0.0.1) cannot be used as an office Wi-Fi network.' });
  }

  // Strictly block broad wildcards (Problem 2)
  if (cleanInput === '192.168.0.0/16' || cleanInput === '10.0.0.0/8' || cleanInput === '172.16.0.0/12' || cleanInput === '0.0.0.0/0') {
    return res.status(400).json({ error: 'Broad wildcard subnets are not allowed for security reasons. Please use an exact office public IP or specific subnet.' });
  }

  try {
    if (cleanInput.includes('/')) {
      ipaddr.parseCIDR(cleanInput);
    } else {
      ipaddr.parse(cleanInput);
    }
  } catch (err) {
    return res.status(400).json({ error: `Invalid IP address or CIDR subnet: ${cleanInput}. Example: 103.140.155.115 or 192.168.1.0/24` });
  }

  try {
    const created = await dbHelpers.addNetwork({
      name: name.trim(),
      ip_or_cidr: cleanInput,
      description: description?.trim() || ''
    });
    invalidatePublicIpCache();

    await dbHelpers.addAuditLog({
      userId: req.user.id,
      userName: req.user.name,
      action: 'NETWORK_ADDED',
      details: `Added network rule: ${name} (${cleanInput})`,
      ipAddress: clientIp
    });

    res.json({ success: true, message: 'Office network authorized successfully.', network: created });
  } catch (err) {
    if (err.message?.includes('UNIQUE constraint failed') || err.message?.includes('already configured')) {
      return res.status(400).json({ error: 'This IP or CIDR is already configured.' });
    }
    res.status(500).json({ error: 'Failed to add office network.' });
  }
});

// Admin: Delete a network
app.delete('/api/admin/networks/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const clientIp = getClientIp(req);

  if (!id) {
    return res.status(400).json({ error: 'Invalid network ID.' });
  }

  await dbHelpers.deleteNetwork(id);
  invalidatePublicIpCache();

  await dbHelpers.addAuditLog({
    userId: req.user.id,
    userName: req.user.name,
    action: 'NETWORK_DELETED',
    details: `Removed network rule with ID: ${id}`,
    ipAddress: clientIp
  });

  res.json({ success: true, message: 'Network removed from authorized list.' });
});

// Admin: Manage Employees
app.get('/api/admin/employees', requireAdmin, async (req, res) => {
  const employees = await dbHelpers.getAllEmployees();
  res.json({ employees });
});

app.post('/api/admin/employees', requireAdmin, async (req, res) => {
  const { name, email, department, role, pin } = req.body;
  const clientIp = getClientIp(req);

  if (!name || !email || !pin) {
    return res.status(400).json({ error: 'Name, email, and PIN are required.' });
  }

  try {
    const employee = await dbHelpers.createEmployee({
      name,
      email,
      department,
      role: role || 'employee',
      pin: String(pin).trim()
    });

    await dbHelpers.addAuditLog({
      userId: req.user.id,
      userName: req.user.name,
      action: 'EMPLOYEE_CREATED',
      details: `Created new staff account: ${employee.name} (${employee.email})`,
      ipAddress: clientIp
    });

    res.json({ success: true, message: 'Employee registered successfully.', employee });
  } catch (err) {
    if (err.message?.includes('UNIQUE constraint failed') || err.message?.includes('already exists')) {
      return res.status(400).json({ error: 'An employee with this email already exists.' });
    }
    res.status(500).json({ error: 'Failed to create employee.' });
  }
});

// Admin: Audit Logs Trail (Problem 11)
app.get('/api/admin/audit-logs', requireAdmin, async (req, res) => {
  const logs = await dbHelpers.getAuditLogs(50);
  res.json({ logs });
});

// Serve static frontend assets
app.use(express.static(path.join(__dirname, '..', 'public')));

// Catch-all route to index.html for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Start server when run directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`[PulseOffice Server] running on http://localhost:${PORT}`);
  });
}

module.exports = app;
