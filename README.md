# PulseOffice — Office Attendance Website

A simple, responsive, and secure **Office Attendance Website** for employees and administrators with server-side office network verification.

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
- **Responsive Across Devices**:
  - Optimized for desktop browsers, laptop browsers, iPhones, and Android phones.
- **Admin Dashboard**:
  - Live KPI summary counters (Today's Present, In Office, Absent, Late Arrivals).
  - Filterable and searchable attendance roster (`Employee | Check In | Check Out | Duration | Status`).
  - Historical attendance viewer by date.
  - **1-Click Export to CSV** for payroll and reporting.
  - **Office Wi-Fi Setup**: Auto-detects connected network and allows 1-click authorization of the office public gateway or local Wi-Fi subnet.
  - Staff management directory (register new employees).
- **Embedded Database**:
  - Zero external database dependencies — uses Node's high-performance built-in SQLite engine (`node:sqlite`).

---

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Server
```bash
npm start
```
The server will run at:
- **Local machine**: `http://localhost:3000`
- **Other devices on office Wi-Fi**: `http://<YOUR_LOCAL_IP>:3000` (e.g. `http://192.168.1.133:3000`)

---

## Default Credentials

| Role | Work Email | PIN / Password |
|---|---|---|
| **Administrator** | `admin@office.local` | `1234` |
| **Employee** | `ven@office.local` | `1234` |

*(Additional employees can be registered anytime from the Admin Console)*

---

## Office Wi-Fi Setup Guide

1. Connect your computer to your office Wi-Fi router.
2. Sign in as Administrator (`admin@office.local` / `1234`).
3. Navigate to the **"Office Wi-Fi & IP"** tab.
4. Click **“Set This Wi-Fi as Office Network”**.
5. The system authorizes the network. Any employee connected to this Wi-Fi can now mark attendance, while mobile hotspots or remote networks will be strictly blocked.

---

## Running Tests

Run the comprehensive automated test suite:
```bash
npm test
```

---

## License

ISC License
