const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'attendance.db');
const db = new DatabaseSync(DB_PATH);

// Helper for password/PIN hashing
function hashPin(pin, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(pin, salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPin(pin, storedHash, salt) {
  const hash = crypto.scryptSync(pin, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

// Format local date YYYY-MM-DD
function getLocalDateString(d = new Date()) {
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

// Initialize tables
function initDb() {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS employees (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_code TEXT UNIQUE,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL DEFAULT 'employee',
      department TEXT,
      pin_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS office_networks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      ip_or_cidr TEXT NOT NULL UNIQUE,
      description TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS attendance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employee_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      date TEXT NOT NULL,
      check_in_time TEXT,
      check_out_time TEXT,
      verification_method TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'present',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY(employee_id) REFERENCES employees(id),
      UNIQUE(employee_id, date)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT UNIQUE NOT NULL,
      employee_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      user_agent TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(employee_id) REFERENCES employees(id)
    );
  `);

  seedInitialData();
}

function seedInitialData() {
  // Check if admin exists
  const adminCheck = db.prepare("SELECT COUNT(*) as count FROM employees WHERE role = 'admin'").get();
  const now = new Date().toISOString();
  const defaultPin = '1234';

  if (adminCheck.count === 0) {
    console.log('[DB] Initializing Administrator account...');
    const { hash, salt } = hashPin(defaultPin);
    const insertEmp = db.prepare(`
      INSERT INTO employees (employee_code, name, email, role, department, pin_hash, salt, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertEmp.run('ADM-001', 'Office Administrator', 'admin@office.local', 'admin', 'Management', hash, salt, now);
  }

  // Check if employee Ven exists
  const venCheck = db.prepare("SELECT COUNT(*) as count FROM employees WHERE email = 'ven@office.local'").get();
  if (venCheck.count === 0) {
    console.log('[DB] Initializing Employee account (Ven)...');
    const { hash, salt } = hashPin(defaultPin);
    const insertEmp = db.prepare(`
      INSERT INTO employees (employee_code, name, email, role, department, pin_hash, salt, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    insertEmp.run('EMP-101', 'Ven', 'ven@office.local', 'employee', 'Engineering', hash, salt, now);
  }

  // Clean up any fake showcase accounts and fake attendance from previous version
  db.exec(`
    DELETE FROM attendance WHERE name IN ('Rahul', 'Sarah Chen', 'Priya Sharma');
    DELETE FROM sessions WHERE employee_id IN (SELECT id FROM employees WHERE email IN ('rahul@office.local', 'sarah@office.local', 'priya@office.local'));
    DELETE FROM employees WHERE email IN ('rahul@office.local', 'sarah@office.local', 'priya@office.local');
    DELETE FROM office_networks WHERE ip_or_cidr IN ('127.0.0.1', '::1');
  `);
}

// Database helper functions
const dbHelpers = {
  db,
  initDb,
  hashPin,
  verifyPin,
  getLocalDateString,

  // Employees
  getEmployeeByEmail(email) {
    const stmt = db.prepare('SELECT * FROM employees WHERE email = ?');
    return stmt.get(email.toLowerCase().trim());
  },
  getEmployeeById(id) {
    const stmt = db.prepare('SELECT id, employee_code, name, email, role, department, created_at FROM employees WHERE id = ?');
    return stmt.get(id);
  },
  getAllEmployees() {
    const stmt = db.prepare('SELECT id, employee_code, name, email, role, department, created_at FROM employees ORDER BY role DESC, name ASC');
    return stmt.all();
  },
  createEmployee({ name, email, role = 'employee', department, pin }) {
    const { hash, salt } = hashPin(pin);
    const now = new Date().toISOString();
    const countStmt = db.prepare("SELECT COUNT(*) as count FROM employees WHERE role = 'employee'");
    const { count } = countStmt.get();
    const code = `EMP-${String(101 + count).padStart(3, '0')}`;

    const stmt = db.prepare(`
      INSERT INTO employees (employee_code, name, email, role, department, pin_hash, salt, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const res = stmt.run(code, name.trim(), email.toLowerCase().trim(), role, department || 'General', hash, salt, now);
    return this.getEmployeeById(res.lastInsertRowid);
  },

  // Sessions
  createSession(employeeId, userAgent = '') {
    const token = crypto.randomBytes(32).toString('hex');
    const now = new Date();
    // 30-day persistent session on trusted device
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const stmt = db.prepare(`
      INSERT INTO sessions (token, employee_id, expires_at, user_agent, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(token, employeeId, expiresAt, userAgent, now.toISOString());
    return { token, expiresAt };
  },
  getSession(token) {
    if (!token) return null;
    const stmt = db.prepare(`
      SELECT s.*, e.name, e.email, e.role, e.department, e.employee_code
      FROM sessions s
      JOIN employees e ON s.employee_id = e.id
      WHERE s.token = ? AND datetime(s.expires_at) > datetime('now')
    `);
    return stmt.get(token);
  },
  deleteSession(token) {
    const stmt = db.prepare('DELETE FROM sessions WHERE token = ?');
    return stmt.run(token);
  },

  // Office Networks
  getAllNetworks() {
    const stmt = db.prepare('SELECT * FROM office_networks ORDER BY id ASC');
    return stmt.all();
  },
  getActiveNetworks() {
    const stmt = db.prepare('SELECT * FROM office_networks WHERE is_active = 1');
    return stmt.all();
  },
  addNetwork({ name, ip_or_cidr, description }) {
    const now = new Date().toISOString();
    const stmt = db.prepare(`
      INSERT INTO office_networks (name, ip_or_cidr, description, is_active, created_at)
      VALUES (?, ?, ?, 1, ?)
    `);
    const res = stmt.run(name.trim(), ip_or_cidr.trim(), description || '', now);
    return db.prepare('SELECT * FROM office_networks WHERE id = ?').get(res.lastInsertRowid);
  },
  deleteNetwork(id) {
    const stmt = db.prepare('DELETE FROM office_networks WHERE id = ?');
    return stmt.run(id);
  },
  clearAllNetworks() {
    const stmt = db.prepare('DELETE FROM office_networks');
    return stmt.run();
  },
  toggleNetwork(id, isActive) {
    const stmt = db.prepare('UPDATE office_networks SET is_active = ? WHERE id = ?');
    return stmt.run(isActive ? 1 : 0, id);
  },

  // Attendance
  getTodayAttendance(employeeId, dateStr = getLocalDateString()) {
    const stmt = db.prepare('SELECT * FROM attendance WHERE employee_id = ? AND date = ?');
    return stmt.get(employeeId, dateStr);
  },
  getAttendanceHistory(employeeId, limit = 30) {
    const stmt = db.prepare(`
      SELECT * FROM attendance
      WHERE employee_id = ?
      ORDER BY date DESC, created_at DESC
      LIMIT ?
    `);
    return stmt.all(employeeId, limit);
  },
  recordCheckIn({ employeeId, name, dateStr, checkInIso, verificationMethod, isLate = false }) {
    const now = new Date().toISOString();
    const status = isLate ? 'late' : 'in_office';
    const stmt = db.prepare(`
      INSERT INTO attendance (employee_id, name, date, check_in_time, check_out_time, verification_method, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)
    `);
    const res = stmt.run(employeeId, name, dateStr, checkInIso, verificationMethod, status, now, now);
    return db.prepare('SELECT * FROM attendance WHERE id = ?').get(res.lastInsertRowid);
  },
  recordCheckOut({ attendanceId, checkOutIso, status = 'present' }) {
    const now = new Date().toISOString();
    const stmt = db.prepare(`
      UPDATE attendance
      SET check_out_time = ?, status = ?, updated_at = ?
      WHERE id = ?
    `);
    stmt.run(checkOutIso, status, now, attendanceId);
    return db.prepare('SELECT * FROM attendance WHERE id = ?').get(attendanceId);
  },
  getAttendanceByDate(dateStr) {
    const stmt = db.prepare(`
      SELECT e.id as employee_id, e.employee_code, e.name, e.department, e.email,
             a.id as attendance_id, a.check_in_time, a.check_out_time,
             a.verification_method, a.status, a.date
      FROM employees e
      LEFT JOIN attendance a ON e.id = a.employee_id AND a.date = ?
      WHERE e.role = 'employee'
      ORDER BY e.name ASC
    `);
    return stmt.all(dateStr);
  },
  getAllAttendanceRecords({ startDate, endDate } = {}) {
    let query = `
      SELECT a.*, e.employee_code, e.department, e.email
      FROM attendance a
      JOIN employees e ON a.employee_id = e.id
    `;
    const params = [];
    if (startDate && endDate) {
      query += ' WHERE a.date BETWEEN ? AND ?';
      params.push(startDate, endDate);
    }
    query += ' ORDER BY a.date DESC, a.check_in_time DESC';
    const stmt = db.prepare(query);
    return stmt.all(...params);
  }
};

// Initialize DB on load
initDb();

module.exports = dbHelpers;
