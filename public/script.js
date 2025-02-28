// public/script.js
document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const verifyForm = document.getElementById('verify-form');
  const resultDiv = document.getElementById('result');
  const loginButton = document.getElementById('login-button');
  const signupButton = document.getElementById('signup-button');
  const authModal = document.getElementById('auth-modal');
  const closeModal = document.getElementById('close-modal');
  const authModalTitle = document.getElementById('auth-modal-title');
  const loginForm = document.getElementById('login-form');
  const signupForm = document.getElementById('signup-form');
  const loginError = document.getElementById('login-error');
  const signupError = document.getElementById('signup-error');
  const logoutButton = document.getElementById('logout-button');
  const authButtons = document.getElementById('auth-buttons');
  const userProfile = document.getElementById('user-profile');
  const usernameDisplay = document.getElementById('username-display');
  const historySection = document.getElementById('history-section');
  const historyList = document.getElementById('history-list');
  
  // Check if user is logged in
  checkAuthStatus();
  
  // Event Listeners
  if (verifyForm) {
    verifyForm.addEventListener('submit', handleVerifySubmit);
  }
  
  if (loginButton) {
    loginButton.addEventListener('click', () => {
      authModalTitle.textContent = 'Sign In';
      loginForm.classList.remove('hidden');
      signupForm.classList.add('hidden');
      authModal.classList.remove('hidden');
    });
  }
  
  if (signupButton) {
    signupButton.addEventListener('click', () => {
      authModalTitle.textContent = 'Create Account';
      loginForm.classList.add('hidden');
      signupForm.classList.remove('hidden');
      authModal.classList.remove('hidden');
    });
  }
  
  if (closeModal) {
    closeModal.addEventListener('click', () => {
      authModal.classList.add('hidden');
      loginError.classList.add('hidden');
      signupError.classList.add('hidden');
    });
  }
  
  if (loginForm) {
    loginForm.addEventListener('submit', handleLoginSubmit);
  }
  
  if (signupForm) {
    signupForm.addEventListener('submit', handleSignupSubmit);
  }
  
  if (logoutButton) {
    logoutButton.addEventListener('click', handleLogout);
  }
  
  // Functions
  async function handleVerifySubmit(event) {
    event.preventDefault();
    
    const url = document.getElementById('article-url').value;
    const text = document.getElementById('article-text').value;
    
    if (!url && !text) {
      resultDiv.innerHTML = '<p class="text-red-500">Please provide either a URL or article text</p>';
      resultDiv.classList.remove('hidden');
      return;
    }
    
    try {
      resultDiv.innerHTML = '<p class="text-blue-500">Analyzing content...</p>';
      resultDiv.classList.remove('hidden');
      
      const response = await fetch('/api/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url, text })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        displayResults(data);
        // Refresh history if user is logged in
        checkAuthStatus();
      } else {
        resultDiv.innerHTML = `<p class="text-red-500">Error: ${data.error || 'Unknown error occurred'}</p>`;
      }
    } catch (error) {
      resultDiv.innerHTML = `<p class="text-red-500">Error: ${error.message}</p>`;
    }
  }
  
  function displayResults(data) {
    const { credibilityScore, summary, recommendation, factors } = data;
    
    let html = `
      <h2 class="text-xl font-bold mb-4">Analysis Results</h2>
      <div class="mb-6">
        <h3 class="text-lg font-semibold">Credibility Score: ${credibilityScore}/100</h3>
        <div class="score-bar">
          <div class="score-fill" style="width: ${credibilityScore}%"></div>
        </div>
        <div class="mt-4">
          <p class="mb-2">${summary}</p>
          <p class="font-semibold">${recommendation}</p>
        </div>
      </div>
      <h3 class="text-lg font-semibold mb-3">Analysis Factors:</h3>
      <div class="space-y-6">
    `;
    
    factors.forEach(factor => {
      html += `
        <div class="border-t pt-4">
          <h4 class="font-semibold">${factor.name}: ${factor.score}/100</h4>
          <div class="factor-bar">
            <div class="factor-fill" style="width: ${factor.score}%"></div>
          </div>
          <p>${factor.description}</p>
        </div>
      `;
    });
    
    html += `</div>`;
    
    resultDiv.innerHTML = html;
    resultDiv.classList.remove('hidden');
  }
  
  async function handleLoginSubmit(event) {
    event.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        // Success - update UI
        authModal.classList.add('hidden');
        updateUIForLoggedInUser(data.user);
        loginForm.reset();
      } else {
        // Show error
        loginError.textContent = data.error || 'Login failed';
        loginError.classList.remove('hidden');
      }
    } catch (error) {
      loginError.textContent = 'An error occurred during login';
      loginError.classList.remove('hidden');
    }
  }
  
  async function handleSignupSubmit(event) {
    event.preventDefault();
    
    const username = document.getElementById('signup-username').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const confirm = document.getElementById('signup-confirm').value;
    
    // Password validation
    if (password !== confirm) {
      signupError.textContent = 'Passwords do not match';
      signupError.classList.remove('hidden');
      return;
    }
    
    try {
      const response = await fetch('/api/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, email, password })
      });
      
      const data = await response.json();
      
      if (response.ok) {
        // Success - update UI
        authModal.classList.add('hidden');
        updateUIForLoggedInUser(data.user);
        signupForm.reset();
      } else {
        // Show error
        signupError.textContent = data.error || 'Signup failed';
        signupError.classList.remove('hidden');
      }
    } catch (error) {
      signupError.textContent = 'An error occurred during signup';
      signupError.classList.remove('hidden');
    }
  }
  
  async function handleLogout() {
    try {
      await fetch('/api/logout', {
        method: 'POST'
      });
      
      // Update UI for logged out state
      updateUIForLoggedOutUser();
    } catch (error) {
      console.error('Logout error:', error);
    }
  }
  
  function updateUIForLoggedInUser(user) {
    authButtons.classList.add('hidden');
    userProfile.classList.remove('hidden');
    usernameDisplay.textContent = user.username;
    
    // Show history section
    historySection.classList.remove('hidden');
    
    // Fetch and display user's verification history
    fetchVerificationHistory();
  }
  
  function updateUIForLoggedOutUser() {
    authButtons.classList.remove('hidden');
    userProfile.classList.add('hidden');
    historySection.classList.add('hidden');
  }
  
  async function checkAuthStatus() {
    try {
      const response = await fetch('/api/profile');
      
      if (response.ok) {
        const data = await response.json();
        updateUIForLoggedInUser(data.user);
      } else {
        updateUIForLoggedOutUser();
      }
    } catch (error) {
      console.error('Auth check error:', error);
      updateUIForLoggedOutUser();
    }
  }
  
  async function fetchVerificationHistory() {
    try {
      const response = await fetch('/api/profile');
      
      if (response.ok) {
        const data = await response.json();
        displayVerificationHistory(data.user.verificationHistory);
      }
    } catch (error) {
      console.error('Error fetching history:', error);
    }
  }
  
  function displayVerificationHistory(history) {
    if (!history || history.length === 0) {
      historyList.innerHTML = '<p class="text-gray-500">No verification history yet.</p>';
      return;
    }
    
    // Sort by most recent first
    const sortedHistory = [...history].sort((a, b) => 
      new Date(b.verifiedAt) - new Date(a.verifiedAt)
    );
    
    let html = '';
    
    sortedHistory.forEach(item => {
      const date = new Date(item.verifiedAt).toLocaleString();
      const sourceText = item.articleUrl 
        ? `<a href="${item.articleUrl}" target="_blank" class="text-blue-600 underline">${item.articleUrl}</a>`
        : 'Text input';
        
      html += `
        <div class="border rounded-lg p-4">
          <div class="flex justify-between items-center mb-2">
            <span class="font-semibold">Score: ${item.credibilityScore}/100</span>
            <span class="text-sm text-gray-500">${date}</span>
          </div>
          <p class="text-sm text-gray-700 truncate">Source: ${sourceText}</p>
        </div>
      `;
    });
    
    historyList.innerHTML = html;
  }
});