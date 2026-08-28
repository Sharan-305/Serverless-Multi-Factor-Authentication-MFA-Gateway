/**
 * Register Page Controller
 */

// Configure API Endpoint (Adjust to match deployed API Gateway or local serverless-offline endpoint)
const API_BASE_URL = window.location.origin && window.location.origin !== 'null' && !window.location.protocol.startsWith('file')
  ? `${window.location.origin}/dev`
  : 'https://localhost:8000/dev';

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('register-form');
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

    const name = document.getElementById('name').value.trim();
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;

    submitBtn.disabled = true;
    btnSpinner.classList.remove('hidden');

    try {
      const response = await fetch(`${API_BASE_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, username, email, password }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        showAlert('Registration successful! Redirecting to login...', 'success');
        setTimeout(() => {
          window.location.href = 'login.html';
        }, 1500);
      } else {
        showAlert(data.error || 'Registration failed. Please check inputs.');
      }
    } catch (err) {
      console.error('Registration fetch error:', err);
      showAlert('Unable to reach server. Please verify your connection.');
    } finally {
      submitBtn.disabled = false;
      btnSpinner.classList.add('hidden');
    }
  });
});
