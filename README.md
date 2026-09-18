# PulseOffice — Office Attendance Website

A simple, responsive, and secure **Office Attendance Website** for employees and administrators with server-side office network verification.

Works seamlessly on **local servers** and **cloud serverless deployments (Vercel + Firebase Firestore)**.

---

## Features

- **Authoritative Server-Side Network Verification**:
  - Validates that attendance requests originate strictly from authorized office Wi-Fi networks (IP addresses or CIDR subnets).
  - Automatically rejects cellular mobile hotspots, home Wi-Fi, and unauthorized external networks with:
    > **“You must be connected to the office Wi-Fi to mark attendance.”**
- **Manual Attendance Workflow**:
  - Employee connects to office Wi-Fi, opens the portal, and clicks **“I’m in Office”**.
  - Server records exact server-side timestamp and marks employee as **Checked In**.
  - Live working duration stopwatch ticks in real time.
  - At the end of the day, employee clicks **“Check Out”** to finalize their hours.
- **Vercel & Firebase Ready**:
  - Pluggable database layer: runs offline locally on embedded SQLite, or connects to **Firebase Firestore** when deployed to **Vercel**.
- **Responsive Across Devices**:
  - Optimized for desktop browsers, laptop browsers, iPhones, and Android phones.
- **Admin Dashboard**:
  - Live KPI summary counters (Today's Present, In Office, Absent, Late Arrivals).
  - Filterable and searchable attendance roster (`Employee | Check In | Check Out | Duration | Status`).
  - Historical attendance viewer by date.
  - **1-Click Export to CSV** for payroll and reporting.
  - **Office Wi-Fi Setup**: Auto-detects connected network and allows 1-click authorization of the office public gateway or local Wi-Fi subnet.
  - Staff management directory (register new employees).

---

## Default Credentials

| Role | Work Email | PIN / Password |
|---|---|---|
| **Administrator** | `admin@office.local` | `1234` |
| **Employee** | `ven@office.local` | `1234` |

*(Additional employees can be registered anytime from the Admin Console)*

---

## Deploying to Vercel with Firebase Firestore

### Step 1: Create a Free Firebase Project
1. Go to [console.firebase.google.com](https://console.firebase.google.com/).
2. Click **Add Project** and give it a name (e.g. `pulse-office`).
3. In the Firebase console left sidebar, navigate to **Build -> Firestore Database**.
4. Click **Create Database** -> Choose **Start in production mode** (or test mode) -> Select a location close to your office.

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

## Office Wi-Fi Setup Guide

1. Connect your computer to your office Wi-Fi router.
2. Sign in as Administrator (`admin@office.local` / `1234`).
3. Navigate to the **"Office Wi-Fi & IP"** tab.
4. Click **“Set This Wi-Fi as Office Network”**.
5. The system authorizes the network. Any employee connected to this Wi-Fi can now mark attendance, while mobile hotspots or remote networks will be strictly blocked.

---

## Running Tests

Run the automated test suite:
```bash
npm test
```

---

## License

ISC License
