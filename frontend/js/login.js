/**
 * Login Page Controller
 */

const API_BASE_URL = window.location.origin && window.location.origin !== 'null' && !window.location.protocol.startsWith('file')
  ? `${window.location.origin}/dev`
  : 'https://localhost:8000/dev';

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('login-form');
  const alertBanner = document.getElementById('alert-banner');
  const submitBtn = document.getElementById('submit-btn');
  const btnSpinner = document.getElementById('btn-spinner');

  function showAlert(message, type = 'error') {
    alertBanner.textContent = message;
    alertBanner.className = `alert alert-${type}`;
  }

  function hideAlert() {
    alertBanner.className = 'alert hidden';
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    submitBtn.disabled = true;
    btnSpinner.classList.remove('hidden');

    try {
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (response.ok && data.success && data.mfa_required) {
        // Store session state in sessionStorage for verification stage
        sessionStorage.setItem('pending_session_id', data.session_id);
        sessionStorage.setItem('pending_user_id', data.user_id);
        sessionStorage.setItem('pending_email', data.email);
        
        if (data.debug_otp) {
          sessionStorage.setItem('debug_otp', data.debug_otp);
        }

        showAlert('Credentials verified. Redirecting to MFA OTP check...', 'info');
        setTimeout(() => {
          window.location.href = 'verify.html';
        }, 1000);
      } else {
        showAlert(data.error || 'Invalid username or password.');
      }
    } catch (err) {
      console.error('Login error:', err);
      showAlert('Unable to reach server. Please try again later.');
    } finally {
      submitBtn.disabled = false;
      btnSpinner.classList.add('hidden');
    }
  });
});
