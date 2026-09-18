/**
 * PulseOffice • Production Client Application Logic
 */

(function () {
  'use strict';

  // Application State
  const state = {
    currentUser: null,
    todayAttendance: null,
    network: {
      clientIp: '--',
      isAuthorized: false,
      matchedNetwork: null,
      activeRulesCount: 0
    },
    adminDate: '',
    adminRecords: [],
    adminSummary: {
      totalEmployees: 0,
      presentCount: 0,
      inOfficeCount: 0,
      absentCount: 0,
      lateCount: 0
    },
    adminAuditLogs: [],
    durationInterval: null,
    clockInterval: null,
    networkPollInterval: null,
    serverTimeOffset: 0
  };

  // DOM Elements cache
  const elements = {
    // Views
    viewLogin: document.getElementById('view-login'),
    viewEmployee: document.getElementById('view-employee'),
    viewAdmin: document.getElementById('view-admin'),

    // Nav
    networkPill: document.getElementById('network-pill'),
    networkPillText: document.getElementById('network-pill-text'),
    networkPillIp: document.getElementById('network-pill-ip'),
    userNavBlock: document.getElementById('user-nav-block'),
    userAvatarInitials: document.getElementById('user-avatar-initials'),
    navUserName: document.getElementById('nav-user-name'),
    navUserRole: document.getElementById('nav-user-role'),
    logoutBtn: document.getElementById('logout-btn'),

    // Login
    loginForm: document.getElementById('login-form'),
    loginEmail: document.getElementById('login-email'),
    loginPin: document.getElementById('login-pin'),
    rememberDevice: document.getElementById('remember-device'),

    // Employee View
    empLiveDate: document.getElementById('emp-live-date'),
    empGreetingText: document.getElementById('emp-greeting-text'),
    empDigitalClock: document.getElementById('emp-digital-clock'),
    empNetworkBanner: document.getElementById('emp-network-banner'),
    empNetTitle: document.getElementById('emp-net-title'),
    empNetDetail: document.getElementById('emp-net-detail'),
    netIconConnected: document.getElementById('net-icon-connected'),
    netIconDisconnected: document.getElementById('net-icon-disconnected'),
    btnRefreshNetwork: document.getElementById('btn-refresh-network'),

    empStatusBadge: document.getElementById('emp-status-badge'),
    empStatusBadgeText: document.getElementById('emp-status-badge-text'),
    btnCheckIn: document.getElementById('btn-check-in'),
    btnCheckOut: document.getElementById('btn-check-out'),
    statusCompletedCard: document.getElementById('status-completed-card'),
    metricCheckInTime: document.getElementById('metric-check-in-time'),
    metricCheckOutTime: document.getElementById('metric-check-out-time'),
    metricWorkDuration: document.getElementById('metric-work-duration'),
    empHistoryTbody: document.getElementById('emp-history-tbody'),
    btnRefreshEmpHistory: document.getElementById('btn-refresh-emp-history'),

    // Admin View
    adminNavTabs: document.querySelectorAll('.admin-nav-tab'),
    adminTabPanes: document.querySelectorAll('.admin-tab-pane'),
    kpiPresentCount: document.getElementById('kpi-present-count'),
    kpiInOfficeCount: document.getElementById('kpi-in-office-count'),
    kpiAbsentCount: document.getElementById('kpi-absent-count'),
    kpiLateCount: document.getElementById('kpi-late-count'),
    adminDatePicker: document.getElementById('admin-date-picker'),
    btnDatePrev: document.getElementById('btn-date-prev'),
    btnDateNext: document.getElementById('btn-date-next'),
    btnDateToday: document.getElementById('btn-date-today'),
    adminSearchInput: document.getElementById('admin-search-input'),
    adminStatusFilter: document.getElementById('admin-status-filter'),
    btnExportCsv: document.getElementById('btn-export-csv'),
    adminAttendanceTbody: document.getElementById('admin-attendance-tbody'),

    // Admin Networks & Employees
    adminDetectedPublicIp: document.getElementById('admin-detected-public-ip'),
    adminDetectedLocalIp: document.getElementById('admin-detected-local-ip'),
    adminDetectedStatus: document.getElementById('admin-detected-status'),
    btnSetCurrentWifi: document.getElementById('btn-set-current-wifi'),
    formAddNetwork: document.getElementById('form-add-network'),
    netInputName: document.getElementById('net-input-name'),
    netInputIp: document.getElementById('net-input-ip'),
    netInputDesc: document.getElementById('net-input-desc'),
    networksTbody: document.getElementById('networks-tbody'),
    btnRefreshNetworks: document.getElementById('btn-refresh-networks'),
    formAddEmployee: document.getElementById('form-add-employee'),
    empNameInput: document.getElementById('emp-name'),
    empEmailInput: document.getElementById('emp-email'),
    empDeptInput: document.getElementById('emp-dept'),
    empRoleInput: document.getElementById('emp-role'),
    empPinInput: document.getElementById('emp-pin'),
    employeesDirectoryTbody: document.getElementById('employees-directory-tbody'),

    // Admin Audit Logs
    auditLogsTbody: document.getElementById('audit-logs-tbody'),
    btnRefreshAudit: document.getElementById('btn-refresh-audit'),

    // Modals
    modalNetworkBlocked: document.getElementById('modal-network-blocked'),
    modalDetectedIp: document.getElementById('modal-detected-ip'),
    btnModalClose: document.getElementById('btn-modal-close'),

    modalChangePin: document.getElementById('modal-change-pin'),
    formChangePin: document.getElementById('form-change-pin'),
    newPinInput: document.getElementById('new-pin-input'),
    confirmPinInput: document.getElementById('confirm-pin-input'),
    changePinError: document.getElementById('change-pin-error'),

    modalConfirmWifi: document.getElementById('modal-confirm-wifi'),
    confirmModalDetectedIp: document.getElementById('confirm-modal-detected-ip'),
    confirmReplaceNetworks: document.getElementById('confirm-replace-networks'),
    btnCancelWifiConfirm: document.getElementById('btn-cancel-wifi-confirm'),
    btnProceedWifiConfirm: document.getElementById('btn-proceed-wifi-confirm'),

    toastContainer: document.getElementById('toast-container')
  };

  // -------------------------------------------------------------
  // API Fetch Helper (Strictly HttpOnly Cookie-based Authentication)
  // -------------------------------------------------------------
  async function apiRequest(endpoint, options = {}) {
    const headers = options.headers || {};
    headers['Content-Type'] = 'application/json';

    try {
      const res = await fetch(endpoint, {
        ...options,
        headers,
        credentials: 'same-origin'
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        if (res.status === 403 && data.code === 'NETWORK_NOT_AUTHORIZED') {
          showNetworkBlockedModal(data.network?.clientIp || state.network.clientIp);
        } else if (res.status === 403 && data.code === 'MUST_CHANGE_PIN') {
          showChangePinModal();
        }
        const error = new Error(data.error || `HTTP error ${res.status}`);
        error.status = res.status;
        error.data = data;
        throw error;
      }

      return data;
    } catch (err) {
      throw err;
    }
  }

  // -------------------------------------------------------------
  // Toast Notifications
  // -------------------------------------------------------------
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    } else if (type === 'error') {
      iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    } else {
      iconSvg = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }

    toast.innerHTML = `${iconSvg}<span>${message}</span>`;
    elements.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function showNetworkBlockedModal(detectedIp) {
    if (elements.modalDetectedIp) {
      elements.modalDetectedIp.textContent = detectedIp || state.network.clientIp || 'External Network';
    }
    elements.modalNetworkBlocked.classList.remove('hidden');
  }

  function closeNetworkBlockedModal() {
    elements.modalNetworkBlocked.classList.add('hidden');
  }

  function showChangePinModal() {
    if (elements.modalChangePin) {
      elements.modalChangePin.classList.remove('hidden');
      if (elements.changePinError) elements.changePinError.classList.add('hidden');
    }
  }

  function hideChangePinModal() {
    if (elements.modalChangePin) {
      elements.modalChangePin.classList.add('hidden');
    }
  }

  // -------------------------------------------------------------
  // View Router
  // -------------------------------------------------------------
  function switchView(viewName) {
    elements.viewLogin.classList.add('hidden');
    elements.viewEmployee.classList.add('hidden');
    elements.viewAdmin.classList.add('hidden');

    if (viewName === 'login') {
      elements.viewLogin.classList.remove('hidden');
      elements.userNavBlock.classList.add('hidden');
    } else if (viewName === 'employee') {
      elements.viewEmployee.classList.remove('hidden');
      elements.userNavBlock.classList.remove('hidden');
      loadEmployeeDashboard();
    } else if (viewName === 'admin') {
      elements.viewAdmin.classList.remove('hidden');
      elements.userNavBlock.classList.remove('hidden');
      loadAdminDashboard();
    }

    updateNavUser();
  }

  function updateNavUser() {
    if (!state.currentUser) {
      elements.userNavBlock.classList.add('hidden');
      return;
    }

    elements.userNavBlock.classList.remove('hidden');
    elements.navUserName.textContent = state.currentUser.name;
    elements.navUserRole.textContent = state.currentUser.role === 'admin' ? 'Administrator' : state.currentUser.department || 'Employee';
    elements.userAvatarInitials.textContent = state.currentUser.name.charAt(0).toUpperCase();
  }

  // -------------------------------------------------------------
  // Network Verification (Status Check)
  // -------------------------------------------------------------
  async function checkNetworkStatus() {
    try {
      const data = await apiRequest('/api/network/status');
      state.network = data.network;

      // Update Nav Indicator
      if (state.network.isAuthorized) {
        elements.networkPill.className = 'network-pill connected';
        elements.networkPillText.textContent = 'Office Network: ✓ Connected';
        elements.networkPillIp.textContent = state.network.clientIp;
      } else {
        elements.networkPill.className = 'network-pill disconnected';
        elements.networkPillText.textContent = 'Office Network: ✗ Disconnected';
        elements.networkPillIp.textContent = state.network.clientIp;
      }

      // Update employee banner if in employee view
      updateEmployeeNetworkBanner();

      return state.network;
    } catch (err) {
      console.warn('Network status check failed:', err);
    }
  }

  function updateEmployeeNetworkBanner() {
    if (!elements.empNetworkBanner) return;

    if (state.network.isAuthorized) {
      elements.empNetworkBanner.className = 'network-status-banner connected';
      elements.empNetTitle.textContent = 'Office Network: ✓ Connected';
      const netName = state.network.matchedNetwork?.name || 'Office Wi-Fi';
      elements.empNetDetail.textContent = `Authorized on ${netName} (IP: ${state.network.clientIp})`;
      elements.netIconConnected.classList.remove('hidden');
      elements.netIconDisconnected.classList.add('hidden');
    } else {
      elements.empNetworkBanner.className = 'network-status-banner disconnected';
      elements.empNetTitle.textContent = 'Office Network: ✗ Outside Office Network';
      elements.empNetDetail.textContent = `Your current IP: ${state.network.clientIp}. You must connect to office Wi-Fi to mark attendance.`;
      elements.netIconConnected.classList.add('hidden');
      elements.netIconDisconnected.classList.remove('hidden');
    }
  }

  // -------------------------------------------------------------
  // Employee Dashboard Logic
  // -------------------------------------------------------------
  async function loadEmployeeDashboard() {
    updateEmployeeGreeting();
    await checkNetworkStatus();
    await loadTodayAttendance();
    await loadEmployeeHistory();
  }

  function updateEmployeeGreeting() {
    const now = new Date();
    const hours = now.getHours();
    let greetingWord = 'Good morning';
    if (hours >= 12 && hours < 17) {
      greetingWord = 'Good afternoon';
    } else if (hours >= 17) {
      greetingWord = 'Good evening';
    }

    const firstName = state.currentUser ? state.currentUser.name.split(' ')[0] : 'Colleague';
    elements.empGreetingText.textContent = `${greetingWord}, ${firstName}`;

    const options = { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' };
    elements.empLiveDate.textContent = now.toLocaleDateString('en-US', options);
  }

  async function loadTodayAttendance() {
    try {
      const data = await apiRequest('/api/attendance/today');
      state.todayAttendance = data.attendance;
      renderEmployeeAttendanceState();
    } catch (err) {
      if (err.status !== 403) {
        console.error('Failed to load today attendance:', err);
        showToast('Could not fetch attendance status', 'error');
      }
    }
  }

  function renderEmployeeAttendanceState() {
    const att = state.todayAttendance;

    if (state.durationInterval) {
      clearInterval(state.durationInterval);
      state.durationInterval = null;
    }

    if (!att || !att.check_in_time) {
      // STATE 1: NOT CHECKED IN
      elements.empStatusBadge.className = 'status-badge status-not-checked-in';
      elements.empStatusBadgeText.textContent = "Not Checked In";

      elements.btnCheckIn.classList.remove('hidden');
      elements.btnCheckOut.classList.add('hidden');
      elements.statusCompletedCard.classList.add('hidden');

      elements.metricCheckInTime.textContent = '—';
      elements.metricCheckOutTime.textContent = '—';
      elements.metricWorkDuration.textContent = '—';

    } else if (att.check_in_time && !att.check_out_time) {
      // STATE 2: CHECKED IN (IN OFFICE)
      elements.empStatusBadge.className = 'status-badge status-checked-in';
      elements.empStatusBadgeText.textContent = `✓ Checked In (${att.check_in_formatted})`;

      elements.btnCheckIn.classList.add('hidden');
      elements.btnCheckOut.classList.remove('hidden');
      elements.statusCompletedCard.classList.add('hidden');

      elements.metricCheckInTime.textContent = att.check_in_formatted;
      elements.metricCheckOutTime.textContent = '—';

      // Live duration stopwatch
      updateLiveDuration(att.check_in_time);
      state.durationInterval = setInterval(() => {
        updateLiveDuration(att.check_in_time);
      }, 1000);

    } else {
      // STATE 3: CHECKED OUT (COMPLETED)
      elements.empStatusBadge.className = 'status-badge status-checked-out';
      elements.empStatusBadgeText.textContent = `Checked Out (${att.check_out_formatted})`;

      elements.btnCheckIn.classList.add('hidden');
      elements.btnCheckOut.classList.add('hidden');
      elements.statusCompletedCard.classList.remove('hidden');

      elements.metricCheckInTime.textContent = att.check_in_formatted;
      elements.metricCheckOutTime.textContent = att.check_out_formatted;
      elements.metricWorkDuration.textContent = att.duration_text || '—';
    }
  }

  function updateLiveDuration(checkInIso) {
    try {
      const start = new Date(checkInIso).getTime();
      const now = Date.now();
      const diffMs = Math.max(0, now - start);

      const totalSeconds = Math.floor(diffMs / 1000);
      const hours = Math.floor(totalSeconds / 3600);
      const minutes = Math.floor((totalSeconds % 3600) / 60);
      const seconds = totalSeconds % 60;

      const formatted = `${hours}h ${String(minutes).padStart(2, '0')}m ${String(seconds).padStart(2, '0')}s`;
      elements.metricWorkDuration.textContent = formatted;
    } catch (e) {
      elements.metricWorkDuration.textContent = '—';
    }
  }

  async function handleCheckIn() {
    elements.btnCheckIn.disabled = true;
    elements.btnCheckIn.style.opacity = '0.6';

    try {
      const data = await apiRequest('/api/attendance/check-in', {
        method: 'POST'
      });

      showToast(data.message || 'Checked in successfully!', 'success');
      state.todayAttendance = data.attendance;
      renderEmployeeAttendanceState();
      loadEmployeeHistory();
    } catch (err) {
      if (err.status !== 403) {
        showToast(err.message, 'error');
      }
    } finally {
      elements.btnCheckIn.disabled = false;
      elements.btnCheckIn.style.opacity = '1';
    }
  }

  async function handleCheckOut() {
    elements.btnCheckOut.disabled = true;
    elements.btnCheckOut.style.opacity = '0.6';

    try {
      const data = await apiRequest('/api/attendance/check-out', {
        method: 'POST'
      });

      showToast(data.message || 'Checked out successfully!', 'success');
      state.todayAttendance = data.attendance;
      renderEmployeeAttendanceState();
      loadEmployeeHistory();
    } catch (err) {
      if (err.status !== 403) {
        showToast(err.message, 'error');
      }
    } finally {
      elements.btnCheckOut.disabled = false;
      elements.btnCheckOut.style.opacity = '1';
    }
  }

  async function loadEmployeeHistory() {
    try {
      const data = await apiRequest('/api/attendance/history');
      renderEmployeeHistory(data.history);
    } catch (err) {
      console.warn('Failed to load history:', err);
    }
  }

  function renderEmployeeHistory(history) {
    if (!elements.empHistoryTbody) return;

    if (!history || history.length === 0) {
      elements.empHistoryTbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center py-4" style="color: var(--text-muted);">
            No attendance records recorded yet.
          </td>
        </tr>
      `;
      return;
    }

    elements.empHistoryTbody.innerHTML = history.map(row => {
      let badgeClass = 'badge-present';
      let statusLabel = 'Present';

      if (row.check_in_time && !row.check_out_time) {
        badgeClass = 'badge-office';
        statusLabel = 'In Office';
      } else if (row.status === 'late') {
        badgeClass = 'badge-late';
        statusLabel = 'Late Arrival';
      }

      return `
        <tr>
          <td class="font-mono" style="font-weight: 600;">${row.date}</td>
          <td class="font-mono">${row.check_in_formatted}</td>
          <td class="font-mono">${row.check_out_formatted}</td>
          <td class="font-mono" style="color: #38bdf8; font-weight: 600;">${row.duration_text}</td>
          <td><span style="font-size: 0.78rem; color: var(--text-muted); font-family: var(--font-mono);">${row.verification_method || 'office_wifi'}</span></td>
          <td><span class="badge ${badgeClass}">${statusLabel}</span></td>
        </tr>
      `;
    }).join('');
  }

  // -------------------------------------------------------------
  // Admin Dashboard Logic
  // -------------------------------------------------------------
  async function loadAdminDashboard() {
    if (!state.adminDate) {
      const now = new Date();
      const year = now.getFullYear();
      const month = String(now.getMonth() + 1).padStart(2, '0');
      const day = String(now.getDate()).padStart(2, '0');
      state.adminDate = `${year}-${month}-${day}`;
    }

    if (elements.adminDatePicker) {
      elements.adminDatePicker.value = state.adminDate;
    }

    // Run independent fetches so one failure never blocks the others
    await checkNetworkStatus().catch(console.warn);
    await fetchAdminAttendance().catch(console.warn);
    await fetchAdminNetworks().catch(console.warn);
    await fetchAdminEmployees().catch(console.warn);
    await fetchAdminAuditLogs().catch(console.warn);
  }

  async function fetchAdminAttendance() {
    try {
      const data = await apiRequest(`/api/admin/dashboard?date=${state.adminDate}`);
      state.adminRecords = data.records;
      state.adminSummary = data.summary;

      // Update KPIs with real original metrics
      elements.kpiPresentCount.textContent = state.adminSummary.presentCount;
      elements.kpiInOfficeCount.textContent = state.adminSummary.inOfficeCount;
      elements.kpiAbsentCount.textContent = state.adminSummary.absentCount;
      elements.kpiLateCount.textContent = state.adminSummary.lateCount;

      renderAdminAttendanceTable();
    } catch (err) {
      console.error('Failed to load admin attendance:', err);
      showToast('Could not fetch admin attendance', 'error');
    }
  }

  function renderAdminAttendanceTable() {
    if (!elements.adminAttendanceTbody) return;

    const searchTerm = (elements.adminSearchInput.value || '').toLowerCase().trim();
    const statusFilter = elements.adminStatusFilter.value;

    const filtered = state.adminRecords.filter(rec => {
      const matchesSearch = !searchTerm || 
        rec.name.toLowerCase().includes(searchTerm) || 
        (rec.department && rec.department.toLowerCase().includes(searchTerm)) ||
        (rec.employee_code && rec.employee_code.toLowerCase().includes(searchTerm));

      let matchesStatus = true;
      if (statusFilter !== 'ALL') {
        matchesStatus = rec.status === statusFilter;
      }

      return matchesSearch && matchesStatus;
    });

    if (filtered.length === 0) {
      elements.adminAttendanceTbody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center py-4" style="color: var(--text-muted);">
            No employee records found.
          </td>
        </tr>
      `;
      return;
    }

    elements.adminAttendanceTbody.innerHTML = filtered.map(rec => {
      let badgeClass = 'badge-present';
      if (rec.status === 'In Office') {
        badgeClass = 'badge-office';
      } else if (rec.status === 'Late') {
        badgeClass = 'badge-late';
      } else if (rec.status === 'Absent') {
        badgeClass = 'badge-absent';
      }

      return `
        <tr>
          <td>
            <div style="display: flex; align-items: center; gap: 0.65rem;">
              <div class="chip-avatar" style="width: 28px; height: 28px; font-size: 0.75rem;">
                ${rec.name.charAt(0)}
              </div>
              <div>
                <strong style="display: block; color: var(--text-primary); font-size: 0.92rem;">${rec.name}</strong>
                <span style="font-size: 0.75rem; color: var(--text-muted);">${rec.department || 'Staff'} • ${rec.employee_code || ''}</span>
              </div>
            </div>
          </td>
          <td class="font-mono">${rec.check_in_formatted}</td>
          <td class="font-mono">${rec.check_out_formatted}</td>
          <td class="font-mono" style="color: #38bdf8; font-weight: 600;">${rec.duration_text}</td>
          <td><span class="badge ${badgeClass}">${rec.status}</span></td>
        </tr>
      `;
    }).join('');
  }

  // Admin Networks Management
  async function fetchAdminNetworks() {
    try {
      const data = await apiRequest('/api/admin/networks');
      renderAdminNetworks(data.networks);

      // Update Detected Network Card
      const sys = data.system_info || {};
      const cur = data.current_request || {};

      const detectedWan = (sys.publicIp && sys.publicIp !== 'Unavailable')
        ? sys.publicIp 
        : (state.network.clientIp !== '--' ? state.network.clientIp : 'Unavailable');

      if (elements.adminDetectedPublicIp) {
        elements.adminDetectedPublicIp.textContent = detectedWan;
      }
      if (elements.adminDetectedLocalIp) {
        elements.adminDetectedLocalIp.textContent = (sys.primaryLocalIp && sys.primaryLocalIp !== 'Unavailable')
          ? `${sys.primaryLocalIp} (${sys.primarySubnet || '255.255.255.0'})` 
          : (state.network.clientIp !== '--' ? state.network.clientIp : '--');
      }
      if (elements.adminDetectedStatus) {
        const isAuth = cur.isAuthorized ?? cur.is_authorized ?? state.network.isAuthorized;
        if (isAuth) {
          elements.adminDetectedStatus.innerHTML = `<span class="badge badge-success">✓ Authorized Office Wi-Fi (${cur.matchedNetwork?.name || state.network.matchedNetwork?.name || 'Matched'})</span>`;
        } else {
          elements.adminDetectedStatus.innerHTML = '<span class="badge badge-danger">✗ Outside Office Network / Not Configured</span>';
        }
      }
    } catch (err) {
      console.warn('Failed to fetch networks:', err);
      if (elements.adminDetectedPublicIp && state.network.clientIp !== '--') {
        elements.adminDetectedPublicIp.textContent = state.network.clientIp;
      }
      if (elements.adminDetectedStatus) {
        elements.adminDetectedStatus.innerHTML = state.network.isAuthorized
          ? '<span class="badge badge-success">✓ Authorized Office Wi-Fi</span>'
          : '<span class="badge badge-danger">✗ Outside Office Network / Not Configured</span>';
      }
    }
  }

  function renderAdminNetworks(networks) {
    if (!elements.networksTbody) return;

    if (!networks || networks.length === 0) {
      elements.networksTbody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center py-4" style="color: #fbbf24; font-weight: 500;">
            No office Wi-Fi configured yet. Click "Set This Wi-Fi as Office Network" to authorize your office network.
          </td>
        </tr>
      `;
      return;
    }

    elements.networksTbody.innerHTML = networks.map(net => {
      const statusBadge = net.is_active ? 
        '<span class="badge badge-success">Active</span>' : 
        '<span class="badge badge-absent">Disabled</span>';

      return `
        <tr>
          <td><strong>${net.name}</strong></td>
          <td class="font-mono" style="color: #38bdf8;">${net.ip_or_cidr}</td>
          <td style="font-size: 0.8rem; color: var(--text-muted);">${net.description || '—'}</td>
          <td>${statusBadge}</td>
          <td>
            <button type="button" class="btn-table-del" data-del-net="${net.id}">Delete</button>
          </td>
        </tr>
      `;
    }).join('');

    // Attach delete handlers
    elements.networksTbody.querySelectorAll('[data-del-net]').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const id = e.target.getAttribute('data-del-net');
        if (confirm('Remove this office network?')) {
          try {
            await apiRequest(`/api/admin/networks/${id}`, { method: 'DELETE' });
            showToast('Network removed successfully', 'success');
            await fetchAdminNetworks();
            await checkNetworkStatus();
          } catch (err) {
            showToast(err.message, 'error');
          }
        }
      });
    });
  }

  // Admin Employees
  async function fetchAdminEmployees() {
    try {
      const data = await apiRequest('/api/admin/employees');
      renderAdminEmployees(data.employees);
    } catch (err) {
      console.warn('Failed to fetch employees:', err);
    }
  }

  function renderAdminEmployees(employees) {
    if (!elements.employeesDirectoryTbody) return;

    elements.employeesDirectoryTbody.innerHTML = employees.map(emp => `
      <tr>
        <td class="font-mono" style="font-size: 0.8rem;">${emp.employee_code || '—'}</td>
        <td><strong>${emp.name}</strong></td>
        <td>${emp.email}</td>
        <td>${emp.department || '—'}</td>
        <td><span class="badge ${emp.role === 'admin' ? 'badge-late' : 'badge-office'}">${emp.role}</span></td>
      </tr>
    `).join('');
  }

  // Admin Audit Logs Trail (Problem 11)
  async function fetchAdminAuditLogs() {
    try {
      const data = await apiRequest('/api/admin/audit-logs');
      state.adminAuditLogs = data.logs || [];
      renderAdminAuditLogs();
    } catch (err) {
      console.warn('Failed to fetch audit logs:', err);
    }
  }

  function renderAdminAuditLogs() {
    if (!elements.auditLogsTbody) return;

    if (!state.adminAuditLogs || state.adminAuditLogs.length === 0) {
      elements.auditLogsTbody.innerHTML = `
        <tr>
          <td colspan="5" class="text-center py-4" style="color: var(--text-muted);">
            No audit logs recorded yet.
          </td>
        </tr>
      `;
      return;
    }

    elements.auditLogsTbody.innerHTML = state.adminAuditLogs.map(log => {
      let badgeClass = 'badge-office';
      if (log.action.includes('SUCCESS') || log.action.includes('AUTHORIZED') || log.action.includes('IN')) {
        badgeClass = 'badge-present';
      } else if (log.action.includes('FAILED') || log.action.includes('DELETED')) {
        badgeClass = 'badge-absent';
      } else if (log.action.includes('PIN') || log.action.includes('CREATED')) {
        badgeClass = 'badge-late';
      }

      let timeFormatted = log.created_at;
      try {
        const d = new Date(log.created_at);
        timeFormatted = d.toLocaleString();
      } catch (e) {}

      return `
        <tr>
          <td class="font-mono" style="font-size: 0.8rem; color: var(--text-muted);">${timeFormatted}</td>
          <td><strong>${log.user_name || 'System'}</strong></td>
          <td><span class="badge ${badgeClass}">${log.action}</span></td>
          <td style="font-size: 0.85rem;">${log.details || '—'}</td>
          <td class="font-mono" style="font-size: 0.8rem; color: #38bdf8;">${log.ip_address || '—'}</td>
        </tr>
      `;
    }).join('');
  }

  // -------------------------------------------------------------
  // Digital Clock
  // -------------------------------------------------------------
  function startDigitalClock() {
    function tick() {
      const now = new Date(Date.now() + state.serverTimeOffset);
      let hours = now.getHours();
      const minutes = String(now.getMinutes()).padStart(2, '0');
      const seconds = String(now.getSeconds()).padStart(2, '0');
      const ampm = hours >= 12 ? 'PM' : 'AM';
      hours = hours % 12;
      hours = hours ? hours : 12;
      const hoursStr = String(hours).padStart(2, '0');

      if (elements.empDigitalClock) {
        elements.empDigitalClock.textContent = `${hoursStr}:${minutes}:${seconds} ${ampm}`;
      }
    }

    tick();
    state.clockInterval = setInterval(tick, 1000);
  }

  // -------------------------------------------------------------
  // Event Listeners
  // -------------------------------------------------------------
  function setupEventListeners() {
    // Login form submission
    elements.loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = elements.loginEmail.value.trim();
      const pin = elements.loginPin.value.trim();

      try {
        const data = await apiRequest('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ email, pin })
        });

        state.currentUser = data.user;
        showToast(`Welcome, ${data.user.name}!`, 'success');

        if (data.user.must_change_pin) {
          showChangePinModal();
        } else if (data.user.role === 'admin') {
          switchView('admin');
        } else {
          switchView('employee');
        }
      } catch (err) {
        showToast(err.message || 'Invalid credentials', 'error');
      }
    });

    // Forced PIN Change Form (Problem 6)
    if (elements.formChangePin) {
      elements.formChangePin.addEventListener('submit', async (e) => {
        e.preventDefault();
        const newPin = elements.newPinInput.value.trim();
        const confirmPin = elements.confirmPinInput.value.trim();

        if (newPin.length < 4) {
          elements.changePinError.textContent = 'PIN must be at least 4 digits.';
          elements.changePinError.classList.remove('hidden');
          return;
        }

        if (newPin !== confirmPin) {
          elements.changePinError.textContent = 'PINs do not match. Please re-enter.';
          elements.changePinError.classList.remove('hidden');
          return;
        }

        if (newPin === '1234' || newPin === '0000' || newPin === '1111') {
          elements.changePinError.textContent = 'PIN is too weak. Please choose a secure non-default PIN.';
          elements.changePinError.classList.remove('hidden');
          return;
        }

        try {
          await apiRequest('/api/auth/change-pin', {
            method: 'POST',
            body: JSON.stringify({ newPin })
          });

          if (state.currentUser) {
            state.currentUser.must_change_pin = false;
          }

          hideChangePinModal();
          showToast('PIN updated successfully. Your account is secured!', 'success');

          if (state.currentUser?.role === 'admin') {
            switchView('admin');
          } else {
            switchView('employee');
          }
        } catch (err) {
          elements.changePinError.textContent = err.message || 'Failed to update PIN.';
          elements.changePinError.classList.remove('hidden');
        }
      });
    }

    // Logout button
    elements.logoutBtn.addEventListener('click', async () => {
      try {
        await apiRequest('/api/auth/logout', { method: 'POST' });
      } catch (e) {}
      state.currentUser = null;
      state.todayAttendance = null;
      showToast('Logged out successfully', 'info');
      switchView('login');
    });

    // Employee attendance buttons
    elements.btnCheckIn.addEventListener('click', handleCheckIn);
    elements.btnCheckOut.addEventListener('click', handleCheckOut);
    elements.btnRefreshNetwork.addEventListener('click', async () => {
      await checkNetworkStatus();
      showToast('Office network connection verified', 'info');
    });
    elements.btnRefreshEmpHistory.addEventListener('click', loadEmployeeHistory);

    // Modal close
    elements.btnModalClose.addEventListener('click', closeNetworkBlockedModal);
    elements.modalNetworkBlocked.addEventListener('click', (e) => {
      if (e.target === elements.modalNetworkBlocked) {
        closeNetworkBlockedModal();
      }
    });

    // Admin Navigation Tabs
    elements.adminNavTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        elements.adminNavTabs.forEach(t => t.classList.remove('active'));
        elements.adminTabPanes.forEach(p => p.classList.remove('active'));

        tab.classList.add('active');
        const targetId = tab.getAttribute('data-target');
        const targetPane = document.getElementById(targetId);
        if (targetPane) targetPane.classList.add('active');

        if (targetId === 'admin-tab-networks') {
          fetchAdminNetworks();
        } else if (targetId === 'admin-tab-audit') {
          fetchAdminAuditLogs();
        } else if (targetId === 'admin-tab-employees') {
          fetchAdminEmployees();
        } else if (targetId === 'admin-tab-today') {
          fetchAdminAttendance();
        }
      });
    });

    // Admin Date Stepper
    elements.adminDatePicker.addEventListener('change', (e) => {
      state.adminDate = e.target.value;
      fetchAdminAttendance();
    });

    elements.btnDatePrev.addEventListener('click', () => {
      const d = new Date(state.adminDate);
      d.setDate(d.getDate() - 1);
      state.adminDate = d.toISOString().split('T')[0];
      elements.adminDatePicker.value = state.adminDate;
      fetchAdminAttendance();
    });

    elements.btnDateNext.addEventListener('click', () => {
      const d = new Date(state.adminDate);
      d.setDate(d.getDate() + 1);
      state.adminDate = d.toISOString().split('T')[0];
      elements.adminDatePicker.value = state.adminDate;
      fetchAdminAttendance();
    });

    elements.btnDateToday.addEventListener('click', () => {
      state.adminDate = new Date().toISOString().split('T')[0];
      elements.adminDatePicker.value = state.adminDate;
      fetchAdminAttendance();
    });

    // Admin Filter & Search
    elements.adminSearchInput.addEventListener('input', renderAdminAttendanceTable);
    elements.adminStatusFilter.addEventListener('change', renderAdminAttendanceTable);

    // Admin CSV Export
    elements.btnExportCsv.addEventListener('click', () => {
      const exportUrl = `/api/admin/export-csv?date=${state.adminDate}`;
      const downloadLink = document.createElement('a');
      downloadLink.href = exportUrl;
      downloadLink.setAttribute('download', `office_attendance_${state.adminDate}.csv`);
      document.body.appendChild(downloadLink);
      downloadLink.click();
      downloadLink.remove();
      showToast('Exporting attendance CSV...', 'success');
    });

    // Admin: Set Current Wi-Fi with Explicit Confirmation (Problem 10)
    elements.btnSetCurrentWifi.addEventListener('click', () => {
      const detectedIp = elements.adminDetectedPublicIp?.textContent || state.network.clientIp;
      if (elements.confirmModalDetectedIp) {
        elements.confirmModalDetectedIp.textContent = detectedIp;
      }
      if (elements.modalConfirmWifi) {
        elements.modalConfirmWifi.classList.remove('hidden');
      }
    });

    if (elements.btnCancelWifiConfirm) {
      elements.btnCancelWifiConfirm.addEventListener('click', () => {
        elements.modalConfirmWifi.classList.add('hidden');
      });
    }

    if (elements.btnProceedWifiConfirm) {
      elements.btnProceedWifiConfirm.addEventListener('click', async () => {
        const replaceAll = elements.confirmReplaceNetworks ? elements.confirmReplaceNetworks.checked : false;
        try {
          const res = await apiRequest('/api/admin/networks/set-current', {
            method: 'POST',
            body: JSON.stringify({ confirmed: true, replaceAll })
          });

          elements.modalConfirmWifi.classList.add('hidden');
          showToast(res.message || 'Office Wi-Fi authorized successfully!', 'success');
          await fetchAdminNetworks();
          await checkNetworkStatus();
        } catch (err) {
          showToast(err.message, 'error');
        }
      });
    }

    // Admin: Add Custom Network Form
    elements.formAddNetwork.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = elements.netInputName.value.trim();
      const ip_or_cidr = elements.netInputIp.value.trim();
      const description = elements.netInputDesc.value.trim();

      try {
        await apiRequest('/api/admin/networks', {
          method: 'POST',
          body: JSON.stringify({ name, ip_or_cidr, description })
        });

        showToast('Office network authorized!', 'success');
        elements.formAddNetwork.reset();
        await fetchAdminNetworks();
        await checkNetworkStatus();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    elements.btnRefreshNetworks.addEventListener('click', async () => {
      await fetchAdminNetworks();
      showToast('Network list refreshed', 'info');
    });

    if (elements.btnRefreshAudit) {
      elements.btnRefreshAudit.addEventListener('click', async () => {
        await fetchAdminAuditLogs();
        showToast('Audit logs refreshed', 'info');
      });
    }

    // Admin: Register Employee Form
    elements.formAddEmployee.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = elements.empNameInput.value.trim();
      const email = elements.empEmailInput.value.trim();
      const department = elements.empDeptInput.value.trim();
      const role = elements.empRoleInput.value;
      const pin = elements.empPinInput.value.trim();

      try {
        await apiRequest('/api/admin/employees', {
          method: 'POST',
          body: JSON.stringify({ name, email, department, role, pin })
        });

        showToast(`Employee ${name} registered!`, 'success');
        elements.formAddEmployee.reset();
        await fetchAdminEmployees();
        await fetchAdminAttendance();
      } catch (err) {
        showToast(err.message, 'error');
      }
    });

    // Window visibility change -> recheck status
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        checkNetworkStatus();
        if (state.currentUser && state.currentUser.role !== 'admin') {
          loadTodayAttendance();
        }
      }
    });
  }

  // -------------------------------------------------------------
  // Initial Boot (Cookie-only session detection)
  // -------------------------------------------------------------
  async function initApp() {
    startDigitalClock();
    setupEventListeners();

    // Check initial network status
    await checkNetworkStatus();

    // Auto-login check via HttpOnly cookie
    try {
      const data = await apiRequest('/api/auth/me');
      if (data && data.user) {
        state.currentUser = data.user;
        if (data.user.must_change_pin) {
          showChangePinModal();
        } else if (data.user.role === 'admin') {
          switchView('admin');
        } else {
          switchView('employee');
        }
      } else {
        switchView('login');
      }
    } catch (err) {
      switchView('login');
    }

    // Polling network every 10s
    state.networkPollInterval = setInterval(checkNetworkStatus, 10000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }

})();
