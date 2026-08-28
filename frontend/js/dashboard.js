/**
 * Dashboard Controller (PEP Authorization Gated Page)
 */

const API_BASE_URL = window.location.origin && window.location.origin !== 'null' && !window.location.protocol.startsWith('file')
  ? `${window.location.origin}/dev`
  : 'https://localhost:8000/dev';

document.addEventListener('DOMContentLoaded', async () => {
  const token = localStorage.getItem('jwt_token');

  const profileLoading = document.getElementById('profile-loading');
  const profileContent = document.getElementById('profile-content');
  const auditLoading = document.getElementById('audit-loading');
  const auditContent = document.getElementById('audit-content');
  const auditRows = document.getElementById('audit-rows');
  const logoutBtn = document.getElementById('logout-btn');

  // 1. Guard check: Redirect immediately if no token present
  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  // 2. Fetch Protected Dashboard Data using PEP Authorization header
  try {
    const response = await fetch(`${API_BASE_URL}/dashboard-data`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.status === 401 || response.status === 403) {
      // Authorizer PEP denied access or session revoked
      localStorage.removeItem('jwt_token');
      localStorage.removeItem('user_info');
      window.location.href = 'login.html';
      return;
    }

    const data = await response.json();

    if (response.ok && data.success) {
      // Render Profile Data
      document.getElementById('profile-name').textContent = data.user.name || data.user.username;
      document.getElementById('profile-username').textContent = data.user.username;
      document.getElementById('profile-email').textContent = data.user.email;
      document.getElementById('profile-session').textContent = data.session.session_id || 'Active JWT';

      profileLoading.classList.add('hidden');
      profileContent.classList.remove('hidden');

      // Render Audit Log Table
      auditRows.innerHTML = '';
      if (data.audit_logs && data.audit_logs.length > 0) {
        data.audit_logs.forEach(log => {
          const tr = document.createElement('tr');
          const eventBadge = `<span class="badge badge-event">${log.event}</span>`;
          const formattedTime = new Date(log.timestamp).toLocaleString();
          
          tr.innerHTML = `
            <td>${eventBadge}</td>
            <td style="font-family: monospace;">${log.ip_address}</td>
            <td style="color: var(--text-muted);">${formattedTime}</td>
          `;
          auditRows.appendChild(tr);
        });
      } else {
        auditRows.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No audit logs recorded yet.</td></tr>`;
      }

      auditLoading.classList.add('hidden');
      auditContent.classList.remove('hidden');
    } else {
      localStorage.removeItem('jwt_token');
      window.location.href = 'login.html';
    }

  } catch (err) {
    console.error('Error fetching dashboard data:', err);
    profileLoading.innerHTML = `<p style="color: #ef4444; text-align: center;">Error contacting API Gateway.</p>`;
  }

  // 3. Logout Action
  logoutBtn.addEventListener('click', async () => {
    try {
      await fetch(`${API_BASE_URL}/logout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });
    } catch (e) {
      console.warn('Logout endpoint error:', e);
    } finally {
      localStorage.clear();
      sessionStorage.clear();
      window.location.href = 'login.html';
    }
  });
});
