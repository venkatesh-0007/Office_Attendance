# PulseOffice — Production Office Attendance Website

A simple, responsive, and secure **Office Attendance Website** for employees and administrators with strict server-side office network verification.

Works seamlessly on **local servers** (embedded SQLite) and **serverless cloud deployments** (**Vercel + Firebase Firestore**).

---

## Core Architecture

```
Employee
   ↓
Login
   ↓
Connect to Office Wi-Fi
   ↓
Open website
   ↓
"I'm in Office"
   ↓
Backend
   ↓
Check public IP
   ↓
Matches authorized office IP?
   ├── YES → Record attendance (server timestamp)
   └── NO  → 403 Forbidden ("You must be connected to the office Wi-Fi to mark attendance.")
```

---

## Security & Architecture Hardening

| # | Concern | Solution Implemented |
|---|---|---|
| 1 | **Test Data Isolation** | Uses fresh isolated test database (`test-isolated.db`) for every test run, cleaned up after completion. Dev/prod data is never touched. |
| 2 | **No Broad Networks** | Broad wildcards (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `0.0.0.0/0`) and loopback (`127.0.0.1`) are strictly rejected. Only exact office public IP or specific subnet is authorized. |
| 3 | **Simulator Disabled in Production** | Header simulation is development/test-only (`NODE_ENV === 'test'`). In production, only trusted reverse proxy headers are read. |
| 4 | **Concurrency & Duplicate Guard** | Deterministic doc ID `${employeeId}_${date}` with `.create()` in Firestore (and `UNIQUE(employee_id, date)` in SQLite) guarantees exactly one attendance record even on rapid double-clicks. |
| 5 | **Anti-Spoofing Proxy Trust** | Express `trust proxy` configured safely (`1` / Vercel Edge). Client-supplied `X-Forwarded-For` from untrusted external sources is never blindly trusted. |
| 6 | **Forced Default PIN Change** | Initial default PIN (`1234`) requires a mandatory PIN change before employee or admin can use portal functions. |
| 7 | **Brute-Force Rate Limiting** | 5 consecutive failed login attempts lock out the client/account for 15 minutes (HTTP 429). |
| 8 | **HttpOnly Cookie Auth** | Tokens are stored exclusively in `HttpOnly`, `SameSite=Lax`, `Secure` cookies. Raw tokens are never returned in JSON or saved in browser `localStorage`. |
| 9 | **Short Admin Sessions** | Admin sessions expire in 4 hours; employee sessions last 30 days. Logout immediately revokes the session on the server. |
| 10 | **Network Confirmation Dialog** | Authorizing detected office Wi-Fi displays the detected IP and requires explicit admin confirmation before updating. |
| 11 | **Immutable Audit Trail** | All logins, attendance checks, PIN updates, and network modifications are recorded in an audit log with timestamps, user IDs, and IP addresses. |
| 12 | **Office Network Statement** | Clearly verifies connection to authorized office Wi-Fi networks. |
| 13 | **Vercel Public IP Verification** | When hosted on Vercel, requests are verified against the office's outgoing public WAN IP. |
| 14 | **Dynamic IP Support** | Admin console provides a 1-click update with confirmation if ISP public IP changes. |
| 15 | **Database Layer** | Cloud Firestore for serverless Vercel; embedded SQLite for local development. |
| 16 | **3-Network Verification Suite** | Automated tests verify: Office Wi-Fi ($\checkmark$), Home Wi-Fi ($\times$), and Mobile Hotspot ($\times$). |

---

## Default Credentials

| Role | Work Email | Initial PIN | Action Required |
|---|---|---|---|
| **Administrator** | `admin@office.local` | `1234` | **Prompted to set custom secure PIN on first login** |
| **Employee** | `ven@office.local` | `1234` | **Prompted to set custom secure PIN on first login** |

*(Additional employees can be registered anytime from the Admin Console)*

---

## 3-Network Testing Matrix

```
Office Wi-Fi  ──→  "I'm in Office"  ──→  ✓ MUST WORK (200 OK)
Home Wi-Fi    ──→  "I'm in Office"  ──→  ✗ MUST BE REJECTED (403 Forbidden)
Mobile 4G/5G  ──→  "I'm in Office"  ──→  ✗ MUST BE REJECTED (403 Forbidden)
```

Also verified in test suite:
- **Double-click** $\rightarrow$ Only 1 attendance record created (second rejected with 400).
- **Refresh** $\rightarrow$ Attendance status and timer remain identical.
- **Logout / Login** $\rightarrow$ Attendance status retained across sessions.
- **Laptop $\rightarrow$ Phone** $\rightarrow$ Same employee sees identical checked-in status across multiple devices.
- **Check out twice** $\rightarrow$ Second checkout attempt rejected.
- **Check out first** $\rightarrow$ Attempting to check out before checking in is rejected.
- **Next day** $\rightarrow$ Automatically resets to "Not Checked In" on new calendar date.

---

## Deploying to Vercel with Firebase Firestore

### Step 1: Create a Free Firebase Project
1. Go to [console.firebase.google.com](https://console.firebase.google.com/).
2. Click **Add Project** and give it a name (e.g. `pulse-office`).
3. In the Firebase console left sidebar, navigate to **Build -> Firestore Database**.
4. Click **Create Database** -> Choose **Start in production mode** -> Select a location close to your office.

### Step 2: Generate Service Account Key
1. In Firebase Console, click the **Gear Icon (Project Settings)** in the top left.
2. Go to the **Service Accounts** tab.
3. Click **Generate new private key** -> Click **Generate key**.
4. A JSON file will download to your computer. Open it in a text editor.

### Step 3: Deploy to Vercel
1. Push this repository to your GitHub:
   ```bash
   git push origin main
   ```
2. Go to [vercel.com](https://vercel.com/) and click **Add New -> Project**.
3. Import your GitHub repository (`Office_Attendance`).
4. In **Environment Variables**, add the values from your downloaded Firebase JSON:
   - `FIREBASE_PROJECT_ID`: your project id
   - `FIREBASE_CLIENT_EMAIL`: the `client_email` value
   - `FIREBASE_PRIVATE_KEY`: the entire `private_key` string (including `-----BEGIN PRIVATE KEY-----` and `-----END PRIVATE KEY-----`)
5. Click **Deploy**!

---

## Local Development (Offline with SQLite)

To run the application locally on your computer:
```bash
# 1. Install dependencies
npm install

# 2. Start server
npm start
```
Open **`http://localhost:3000`** in your browser.

---

## Running Automated Tests

Run the automated test suite with isolated database execution:
```bash
npm test
```

---

## License

ISC License
