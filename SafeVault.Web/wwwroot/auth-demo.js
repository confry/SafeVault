// auth-demo.js (Register/Login + /me + /admin/dashboard + logout)
const out = document.getElementById('authOut');

const toJson = async (res) => {
  const text = await res.text();
  try { return JSON.parse(text); } catch { return { status: res.status, body: text }; }
};

const post = (url, body) => fetch(url, {
  method: 'POST',
  headers: {'Content-Type':'application/json'},
  body: JSON.stringify(body)
}).then(toJson);

const get = (url) => fetch(url).then(toJson);

// Register
const regForm = document.getElementById('regForm');
if (regForm) {
  regForm.onsubmit = async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.target);
    const payload = {
      username: (fd.get('username') || '').trim(),
      email:    (fd.get('email') || '').trim(),
      password: fd.get('password') || '',
      role:     fd.get('role') || 'User'
    };
    out.textContent = '...';
    out.textContent = JSON.stringify(await post('/auth/register', payload), null, 2);
  };
}

// Login
const loginForm = document.getElementById('loginForm');
if (loginForm) {
  loginForm.onsubmit = async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.target);
    const payload = {
      username: (fd.get('username') || '').trim(),
      password: fd.get('password') || ''
    };
    out.textContent = '...';
    out.textContent = JSON.stringify(await post('/auth/login', payload), null, 2);
  };
}

// /me
const meBtn = document.getElementById('meBtn');
if (meBtn) {
  meBtn.onclick = async ()=>{
    out.textContent = '...';
    out.textContent = JSON.stringify(await get('/me'), null, 2);
  };
}

// /admin/dashboard
const adminBtn = document.getElementById('adminBtn');
if (adminBtn) {
  adminBtn.onclick = async ()=>{
    out.textContent = '...';
    out.textContent = JSON.stringify(await get('/admin/dashboard'), null, 2);
  };
}

// Logout
const logoutBtn = document.getElementById('logoutBtn');
if (logoutBtn) {
  logoutBtn.onclick = async ()=>{
    out.textContent = '...';
    out.textContent = JSON.stringify(await post('/auth/logout', {}), null, 2);
  };
}
