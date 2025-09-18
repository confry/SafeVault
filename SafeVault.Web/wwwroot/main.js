// main.js (validación cliente + POST /submit)
const form = document.getElementById('userForm');
if (form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const data = new FormData(form);
    const username = (data.get('username') || '').trim();
    const email = (data.get('email') || '').trim();

    if (username.includes('<') || username.includes('>') ||
        email.includes('<') || email.includes('>')) {
      document.getElementById('result').textContent =
        'Entrada inválida: no se permiten < ni >.';
      return;
    }

    try {
      const res = await fetch('/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json'},
        body: JSON.stringify({ username, email })
      });

      const text = await res.text();
      let json;
      try { json = JSON.parse(text); } catch { json = { status: res.status, body: text }; }

      document.getElementById('result').textContent =
        JSON.stringify(json, null, 2);
    } catch (err) {
      document.getElementById('result').textContent = `Error: ${err}`;
    }
  });
}
