const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('node:path');
const ipaddr = require('ipaddr.js');

const dbHelpers = require('./db');
const {
  verifyRequestNetwork,
  getSystemNetworkInfo,
  invalidatePublicIpCache,
  normalizeIp
} = require('./networkVerifier');
const { authenticate, requireAuth, requireAdmin } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Enable JSON body parsing & cookie parsing
app.use(express.json());
app.use(cookieParser());

// Trust proxy for reverse proxy setups (Vercel, Cloudflare, AWS ALB)
app.set('trust proxy', true);

// Auth middleware for all routes
app.use(authenticate);

// Format durations in human readable form (e.g. '8h 24m')
function formatDuration(ms) {
  if (ms == null || isNaN(ms) || ms < 0) return '—';
  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  if (hours === 0 && minutes === 0) {
    return '< 1m';
  }
  if (hours === 0) {
    return `${minutes}m`;
  }
  return `${hours}h ${String(minutes).padStart(2, '0')}m`;
}

// Format time string to 12-hour format: '09:18 AM' or '09:18:42 AM'
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
      network: netStatus
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to verify network status.' });
  }
});

// Authentication: Login
app.post('/api/auth/login', async (req, res) => {
  const { email, pin } = req.body;
  if (!email || !pin) {
    return res.status(400).json({ error: 'Work email and PIN/Password are required.' });
  }

  const employee = await dbHelpers.getEmployeeByEmail(email);
  if (!employee) {
    return res.status(401).json({ error: 'Invalid email or PIN.' });
  }

  const isValid = dbHelpers.verifyPin(String(pin).trim(), employee.pin_hash, employee.salt);
  if (!isValid) {
    return res.status(401).json({ error: 'Invalid email or PIN.' });
  }

  const userAgent = req.headers['user-agent'] || '';
  const { token, expiresAt } = await dbHelpers.createSession(employee.id, userAgent);

  // Set persistent cookie (30 days on trusted device)
  res.cookie('session_token', token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production'
  });

  res.json({
    message: 'Login successful',
    token,
    expiresAt,
    user: {
      id: employee.id,
      name: employee.name,
      email: employee.email,
      role: employee.role,
      department: employee.department,
      employee_code: employee.employee_code
    }
  });
});

// Authentication: Current User
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Authentication: Logout
app.post('/api/auth/logout', async (req, res) => {
  if (req.user?.token) {
    await dbHelpers.deleteSession(req.user.token);
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

// Employee Check-In
app.post('/api/attendance/check-in', requireAuth, async (req, res) => {
  // CRITICAL SECURITY REQUIREMENT: Backend authoritatively verifies office network
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
    console.error('Error recording check-in:', err);
    res.status(500).json({ error: 'Failed to record attendance. Please try again.' });
  }
});

// Employee Check-Out
app.post('/api/attendance/check-out', requireAuth, async (req, res) => {
  // CRITICAL SECURITY REQUIREMENT: Backend authoritatively verifies office network
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

// Admin: Get Office Networks and Current System Environment
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

// Admin 1-Click: Set current network as authorized Office Wi-Fi
app.post('/api/admin/networks/set-current', requireAdmin, async (req, res) => {
  const { mode = 'both', custom_name } = req.body;
  const systemInfo = await getSystemNetworkInfo();
  invalidatePublicIpCache();

  // Clear previous office networks so the new Wi-Fi is active and authoritative immediately
  await dbHelpers.clearAllNetworks();

  const added = [];

  if (mode === 'public_ip' || mode === 'both') {
    if (systemInfo.publicIp && systemInfo.publicIp !== 'Unavailable') {
      const net = await dbHelpers.addNetwork({
        name: custom_name || `Office Public Gateway (${systemInfo.publicIp})`,
        ip_or_cidr: systemInfo.publicIp,
        description: 'Office WAN Public IP (Authorized for All Devices on Office Wi-Fi)'
      });
      added.push(net);
    }
  }

  if (mode === 'subnet' || mode === 'both') {
    if (systemInfo.primarySubnet && systemInfo.primarySubnet !== 'Unavailable') {
      const net = await dbHelpers.addNetwork({
        name: `Office Local Subnet (${systemInfo.primarySubnet})`,
        ip_or_cidr: systemInfo.primarySubnet,
        description: `Local Office Wi-Fi Interface (${systemInfo.interfaceName})`
      });
      added.push(net);
    }
  }

  invalidatePublicIpCache();
  const currentNetStatus = await verifyRequestNetwork(req);

  res.json({
    success: true,
    message: 'Office Wi-Fi network updated and activated successfully!',
    networks: await dbHelpers.getAllNetworks(),
    current_request: currentNetStatus
  });
});

// Admin: Add specific Office IP or CIDR
app.post('/api/admin/networks', requireAdmin, async (req, res) => {
  const { name, ip_or_cidr, description } = req.body;

  if (!name || !ip_or_cidr) {
    return res.status(400).json({ error: 'Network name and IP / CIDR are required.' });
  }

  const cleanInput = ip_or_cidr.trim();

  // Guard against loopback
  if (cleanInput === '127.0.0.1' || cleanInput === '::1' || cleanInput === 'localhost') {
    return res.status(400).json({ error: 'Loopback address (127.0.0.1) cannot be used as an office Wi-Fi network.' });
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
    res.json({ success: true, message: 'Office network authorized successfully.', network: created });
  } catch (err) {
    if (err.message?.includes('UNIQUE constraint failed') || err.message?.includes('already configured')) {
      return res.status(400).json({ error: 'This IP or CIDR is already configured.' });
    }
    res.status(500).json({ error: 'Failed to add office network.' });
  }
});

// Admin: Clear all office networks
app.post('/api/admin/networks/clear-all', requireAdmin, async (req, res) => {
  await dbHelpers.clearAllNetworks();
  invalidatePublicIpCache();
  res.json({ success: true, message: 'All configured office networks cleared.' });
});

// Admin: Delete a network
app.delete('/api/admin/networks/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  if (!id) {
    return res.status(400).json({ error: 'Invalid network ID.' });
  }

  await dbHelpers.deleteNetwork(id);
  invalidatePublicIpCache();
  res.json({ success: true, message: 'Network removed from authorized list.' });
});

// Admin: Manage Employees
app.get('/api/admin/employees', requireAdmin, async (req, res) => {
  const employees = await dbHelpers.getAllEmployees();
  res.json({ employees });
});

app.post('/api/admin/employees', requireAdmin, async (req, res) => {
  const { name, email, department, role, pin } = req.body;

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
    res.json({ success: true, message: 'Employee registered successfully.', employee });
  } catch (err) {
    if (err.message?.includes('UNIQUE constraint failed') || err.message?.includes('already exists')) {
      return res.status(400).json({ error: 'An employee with this email already exists.' });
    }
    res.status(500).json({ error: 'Failed to create employee.' });
  }
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
