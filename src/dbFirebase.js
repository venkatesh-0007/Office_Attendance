const admin = require('firebase-admin');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

let firestoreDb = null;

// Helpers for password/PIN hashing
function hashPin(pin, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(pin, salt, 64).toString('hex');
  return { hash, salt };
}

function verifyPin(pin, storedHash, salt) {
  const hash = crypto.scryptSync(pin, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

function getLocalDateString(d = new Date()) {
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/**
 * Initialize Firebase Admin connection
 */
function getFirestore() {
  if (firestoreDb) return firestoreDb;

  if (admin.apps.length > 0) {
    firestoreDb = admin.firestore();
    return firestoreDb;
  }

  let credential = null;

  // 1. JSON string in environment variable
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    try {
      const parsed = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
      credential = admin.credential.cert(parsed);
    } catch (e) {
      console.error('[Firebase] Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON:', e);
    }
  }
  // 2. Individual environment variables (Standard for Vercel)
  else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
    let privateKey = process.env.FIREBASE_PRIVATE_KEY;
    if (privateKey.startsWith('"') && privateKey.endsWith('"')) {
      privateKey = privateKey.slice(1, -1);
    }
    privateKey = privateKey.replace(/\\n/g, '\n');

    credential = admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: privateKey
    });
  }
  // 3. Local service account JSON file
  else {
    const localJsonPath = path.join(__dirname, '..', 'firebase-service-account.json');
    if (fs.existsSync(localJsonPath)) {
      const serviceAccount = JSON.parse(fs.readFileSync(localJsonPath, 'utf8'));
      credential = admin.credential.cert(serviceAccount);
    }
  }

  if (credential) {
    admin.initializeApp({ credential });
    firestoreDb = admin.firestore();
    console.log('[Firebase] Connected to Firestore cloud database!');
    seedInitialAdmin();
  } else {
    throw new Error('Firebase credentials not found. Please set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY.');
  }

  return firestoreDb;
}

// Seed admin and Ven if empty
async function seedInitialAdmin() {
  try {
    const db = getFirestore();
    const adminSnap = await db.collection('employees').where('email', '==', 'admin@office.local').limit(1).get();
    const now = new Date().toISOString();
    const defaultPin = '1234';

    if (adminSnap.empty) {
      console.log('[Firebase] Seeding Administrator account...');
      const { hash, salt } = hashPin(defaultPin);
      await db.collection('employees').add({
        employee_code: 'ADM-001',
        name: 'Office Administrator',
        email: 'admin@office.local',
        role: 'admin',
        department: 'Management',
        pin_hash: hash,
        salt: salt,
        created_at: now
      });
    }

    const venSnap = await db.collection('employees').where('email', '==', 'ven@office.local').limit(1).get();
    if (venSnap.empty) {
      console.log('[Firebase] Seeding Employee account (Ven)...');
      const { hash, salt } = hashPin(defaultPin);
      await db.collection('employees').add({
        employee_code: 'EMP-101',
        name: 'Ven',
        email: 'ven@office.local',
        role: 'employee',
        department: 'Engineering',
        pin_hash: hash,
        salt: salt,
        created_at: now
      });
    }
  } catch (err) {
    console.warn('[Firebase] Seed check warning:', err.message);
  }
}

const firebaseHelpers = {
  getFirestore,
  hashPin,
  verifyPin,
  getLocalDateString,

  // Employees
  async getEmployeeByEmail(email) {
    const db = getFirestore();
    const snap = await db.collection('employees').where('email', '==', email.toLowerCase().trim()).limit(1).get();
    if (snap.empty) return null;
    const doc = snap.docs[0];
    return { id: doc.id, ...doc.data() };
  },

  async getEmployeeById(id) {
    const db = getFirestore();
    const doc = await db.collection('employees').doc(String(id)).get();
    if (!doc.exists) return null;
    return { id: doc.id, ...doc.data() };
  },

  async getAllEmployees() {
    const db = getFirestore();
    const snap = await db.collection('employees').get();
    const list = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    list.sort((a, b) => a.name.localeCompare(b.name));
    return list;
  },

  async createEmployee({ name, email, role = 'employee', department, pin }) {
    const db = getFirestore();
    const existing = await this.getEmployeeByEmail(email);
    if (existing) {
      throw new Error('An employee with this email already exists.');
    }

    const { hash, salt } = hashPin(pin);
    const now = new Date().toISOString();
    const countSnap = await db.collection('employees').where('role', '==', 'employee').get();
    const code = `EMP-${String(101 + countSnap.size).padStart(3, '0')}`;

    const docRef = await db.collection('employees').add({
      employee_code: code,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      role,
      department: department || 'General',
      pin_hash: hash,
      salt,
      created_at: now
    });

    return {
      id: docRef.id,
      employee_code: code,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      role,
      department: department || 'General',
      created_at: now
    };
  },

  // Sessions
  async createSession(employeeId, userAgent = '') {
    const db = getFirestore();
    const token = crypto.randomBytes(32).toString('hex');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();

    const emp = await this.getEmployeeById(employeeId);

    await db.collection('sessions').doc(token).set({
      token,
      employee_id: employeeId,
      name: emp?.name || '',
      email: emp?.email || '',
      role: emp?.role || 'employee',
      department: emp?.department || '',
      employee_code: emp?.employee_code || '',
      expires_at: expiresAt,
      user_agent: userAgent,
      created_at: now.toISOString()
    });

    return { token, expiresAt };
  },

  async getSession(token) {
    if (!token) return null;
    const db = getFirestore();
    const doc = await db.collection('sessions').doc(token).get();
    if (!doc.exists) return null;
    const data = doc.data();

    // Check expiration
    if (new Date(data.expires_at) <= new Date()) {
      await db.collection('sessions').doc(token).delete();
      return null;
    }
    return data;
  },

  async deleteSession(token) {
    if (!token) return;
    const db = getFirestore();
    await db.collection('sessions').doc(token).delete();
  },

  // Office Networks
  async getAllNetworks() {
    const db = getFirestore();
    const snap = await db.collection('office_networks').get();
    return snap.docs.map(d => ({ id: d.id, ...d.data() }));
  },

  async getActiveNetworks() {
    const db = getFirestore();
    const snap = await db.collection('office_networks').where('is_active', '==', 1).get();
    return snap.docs.map(d => ({ id: d.id, ...d.data() }));
  },

  async addNetwork({ name, ip_or_cidr, description }) {
    const db = getFirestore();
    const now = new Date().toISOString();

    const docRef = await db.collection('office_networks').add({
      name: name.trim(),
      ip_or_cidr: ip_or_cidr.trim(),
      description: description || '',
      is_active: 1,
      created_at: now
    });

    return {
      id: docRef.id,
      name: name.trim(),
      ip_or_cidr: ip_or_cidr.trim(),
      description: description || '',
      is_active: 1,
      created_at: now
    };
  },

  async deleteNetwork(id) {
    const db = getFirestore();
    await db.collection('office_networks').doc(String(id)).delete();
  },

  async clearAllNetworks() {
    const db = getFirestore();
    const snap = await db.collection('office_networks').get();
    const batch = db.batch();
    snap.docs.forEach(doc => batch.delete(doc.ref));
    await batch.commit();
  },

  async toggleNetwork(id, isActive) {
    const db = getFirestore();
    await db.collection('office_networks').doc(String(id)).update({
      is_active: isActive ? 1 : 0
    });
  },

  // Attendance
  async getTodayAttendance(employeeId, dateStr = getLocalDateString()) {
    const db = getFirestore();
    const snap = await db.collection('attendance')
      .where('employee_id', '==', employeeId)
      .where('date', '==', dateStr)
      .limit(1)
      .get();

    if (snap.empty) return null;
    const doc = snap.docs[0];
    return { id: doc.id, ...doc.data() };
  },

  async getAttendanceHistory(employeeId, limit = 30) {
    const db = getFirestore();
    const snap = await db.collection('attendance')
      .where('employee_id', '==', employeeId)
      .get();

    const list = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    list.sort((a, b) => b.date.localeCompare(a.date) || (b.created_at || '').localeCompare(a.created_at || ''));
    return list.slice(0, limit);
  },

  async recordCheckIn({ employeeId, name, dateStr, checkInIso, verificationMethod, isLate = false }) {
    const db = getFirestore();
    const now = new Date().toISOString();
    const status = isLate ? 'late' : 'in_office';

    const docRef = await db.collection('attendance').add({
      employee_id: employeeId,
      name,
      date: dateStr,
      check_in_time: checkInIso,
      check_out_time: null,
      verification_method: verificationMethod,
      status,
      created_at: now,
      updated_at: now
    });

    return {
      id: docRef.id,
      employee_id: employeeId,
      name,
      date: dateStr,
      check_in_time: checkInIso,
      check_out_time: null,
      verification_method: verificationMethod,
      status,
      created_at: now,
      updated_at: now
    };
  },

  async recordCheckOut({ attendanceId, checkOutIso, status = 'present' }) {
    const db = getFirestore();
    const now = new Date().toISOString();

    const docRef = db.collection('attendance').doc(String(attendanceId));
    await docRef.update({
      check_out_time: checkOutIso,
      status,
      updated_at: now
    });

    const doc = await docRef.get();
    return { id: doc.id, ...doc.data() };
  },

  async getAttendanceByDate(dateStr) {
    const db = getFirestore();
    const empSnap = await db.collection('employees').where('role', '==', 'employee').get();
    const attSnap = await db.collection('attendance').where('date', '==', dateStr).get();

    const attMap = new Map();
    attSnap.docs.forEach(d => {
      const data = d.data();
      attMap.set(data.employee_id, { id: d.id, ...data });
    });

    const results = [];
    empSnap.docs.forEach(d => {
      const emp = d.data();
      const att = attMap.get(d.id);
      results.push({
        employee_id: d.id,
        employee_code: emp.employee_code,
        name: emp.name,
        department: emp.department,
        email: emp.email,
        attendance_id: att ? att.id : null,
        date: dateStr,
        check_in_time: att ? att.check_in_time : null,
        check_out_time: att ? att.check_out_time : null,
        verification_method: att ? att.verification_method : null,
        status: att ? att.status : null
      });
    });

    results.sort((a, b) => a.name.localeCompare(b.name));
    return results;
  },

  async getAllAttendanceRecords({ startDate, endDate } = {}) {
    const db = getFirestore();
    const attSnap = await db.collection('attendance').get();
    const empSnap = await db.collection('employees').get();

    const empMap = new Map();
    empSnap.docs.forEach(d => empMap.set(d.id, d.data()));

    let list = attSnap.docs.map(d => {
      const data = d.data();
      const emp = empMap.get(data.employee_id) || {};
      return {
        id: d.id,
        ...data,
        employee_code: emp.employee_code || '',
        department: emp.department || '',
        email: emp.email || ''
      };
    });

    if (startDate && endDate) {
      list = list.filter(r => r.date >= startDate && r.date <= endDate);
    }

    list.sort((a, b) => b.date.localeCompare(a.date) || (b.check_in_time || '').localeCompare(a.check_in_time || ''));
    return list;
  }
};

module.exports = firebaseHelpers;
