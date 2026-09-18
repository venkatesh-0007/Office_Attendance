const fs = require('node:fs');
const path = require('node:path');

const hasFirebaseEnv = Boolean(
  process.env.FIREBASE_SERVICE_ACCOUNT_JSON ||
  (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) ||
  fs.existsSync(path.join(__dirname, '..', 'firebase-service-account.json'))
);

if (hasFirebaseEnv) {
  console.log('[Database] Initializing Cloud Firebase Firestore adapter...');
  module.exports = require('./dbFirebase');
} else {
  console.log('[Database] Initializing Local SQLite adapter...');
  module.exports = require('./dbSqlite');
}
