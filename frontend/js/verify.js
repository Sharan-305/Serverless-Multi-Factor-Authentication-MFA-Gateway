/**
 * OTP Verification Page Controller
 */

const API_BASE_URL = window.location.origin && window.location.origin !== 'null' && !window.location.protocol.startsWith('file')
  ? `${window.location.origin}/dev`
  : 'https://localhost:8000/dev';

document.addEventListener('DOMContentLoaded', () => {
  const sessionId = sessionStorage.getItem('pending_session_id');
  const userEmail = sessionStorage.getItem('pending_email');
  const debugOtp = sessionStorage.getItem('debug_otp');

  const form = document.getElementById('verify-form');
  const alertBanner = document.getElementById('alert-banner');
  const debugBanner = document.getElementById('debug-banner');
  const otpBoxes = document.querySelectorAll('.otp-box');
  const timerElement = document.getElementById('timer');
  const resendLink = document.getElementById('resend-link');
  const submitBtn = document.getElementById('submit-btn');
  const btnSpinner = document.getElementById('btn-spinner');
  const subtitle = document.getElementById('otp-subtitle');

  if (!sessionId) {
    window.location.href = 'login.html';
    return;
  }

  if (userEmail) {
    subtitle.textContent = `Enter the 6-digit code sent to ${userEmail}`;
  }

  if (debugOtp) {
    debugBanner.textContent = `[MOCK / DEV OTP CODE]: ${debugOtp}`;
    debugBanner.classList.remove('hidden');
  }

  // 1. Auto-Focus & Navigation for 6 PIN boxes
  otpBoxes.forEach((box, index) => {
    box.addEventListener('input', (e) => {
      const val = e.target.value;
      if (val && index < otpBoxes.length - 1) {
        otpBoxes[index + 1].focus();
      }
    });

    box.addEventListener('keydown', (e) => {
      if (e.key === 'Backspace' && !e.target.value && index > 0) {
        otpBoxes[index - 1].focus();
      }
    });

    box.addEventListener('paste', (e) => {
      e.preventDefault();
      const pasteData = (e.clipboardData || window.clipboardData).getData('text').trim();
      if (/^\d{6}$/.test(pasteData)) {
        pasteData.split('').forEach((char, i) => {
          if (otpBoxes[i]) otpBoxes[i].value = char;
        });
        otpBoxes[5].focus();
      }
    });
  });

  // 2. Timer Countdown
  let timeLeft = 300; // 5 minutes
  const interval = setInterval(() => {
    if (timeLeft <= 0) {
      clearInterval(interval);
      timerElement.textContent = '00:00';
      timerElement.style.color = '#ef4444';
      showAlert('OTP code expired. Please click "Resend Code".');
      return;
    }
    timeLeft--;
    const mins = Math.floor(timeLeft / 60).toString().padStart(2, '0');
    const secs = (timeLeft % 60).toString().padStart(2, '0');
    timerElement.textContent = `${mins}:${secs}`;
  }, 1000);

  function showAlert(message, type = 'error') {
    alertBanner.textContent = message;
    alertBanner.className = `alert alert-${type}`;
  }

  function hideAlert() {
    alertBanner.className = 'alert hidden';
  }

  // 3. Resend OTP Handler
  resendLink.addEventListener('click', async (e) => {
    e.preventDefault();
    hideAlert();

    try {
      const response = await fetch(`${API_BASE_URL}/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId }),
      });

      const data = await response.json();
      if (response.ok && data.success) {
        timeLeft = 300;
        timerElement.style.color = '#818cf8';
        if (data.debug_otp) {
          debugBanner.textContent = `[MOCK / DEV OTP CODE]: ${data.debug_otp}`;
          debugBanner.classList.remove('hidden');
        }
        showAlert('A fresh OTP code has been sent!', 'success');
      } else {
        showAlert(data.error || 'Failed to resend OTP.');
      }
    } catch (err) {
      showAlert('Unable to dispatch OTP code. Please try again.');
    }
  });

  // 4. Submit Verification Form
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideAlert();

    const otpCode = Array.from(otpBoxes).map((box) => box.value.trim()).join('');
    if (otpCode.length !== 6) {
      showAlert('Please enter all 6 digits of the verification code.');
      return;
    }

    submitBtn.disabled = true;
    btnSpinner.classList.remove('hidden');

    try {
      const response = await fetch(`${API_BASE_URL}/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId, otp: otpCode }),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Clear pending session state & Store JWT Access Token
        sessionStorage.removeItem('pending_session_id');
        sessionStorage.removeItem('debug_otp');

        localStorage.setItem('jwt_token', data.token);
        localStorage.setItem('user_info', JSON.stringify(data.user));

        showAlert('MFA Verification Successful! Loading dashboard...', 'success');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 1200);
      } else {
        showAlert(data.error || 'Invalid OTP verification code.');
      }
    } catch (err) {
      console.error('Verify error:', err);
      showAlert('Server error during verification. Please try again.');
    } finally {
      submitBtn.disabled = false;
      btnSpinner.classList.add('hidden');
    }
  });
});
