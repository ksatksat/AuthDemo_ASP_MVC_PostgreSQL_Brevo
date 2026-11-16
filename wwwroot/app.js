const $ = (id) => document.getElementById(id);

// The session lives in an HttpOnly cookie that only the server can set, read and delete.
// This file only talks to the API and updates the page.

let pendingEmail = "";   // the address a registration code was requested for (kept in memory only)

function show(text, isError = false) {
  const el = $("msg");
  el.textContent = text;           // textContent (not innerHTML) => no XSS
  el.className = "msg" + (isError ? " error" : "");
  el.hidden = !text;
}

async function api(url, method = "GET", body) {
  const headers = { "X-Requested-With": "fetch" };   // required by the server's CSRF guard
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(url, {
    method,
    headers,
    credentials: "same-origin",                       // the browser attaches the cookie itself
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);

  if (!res.ok) {
    // 401 outside login/register => the session ended on the server
    if (res.status === 401 && !url.startsWith("/api/auth/")) {
      render(null);
      throw new Error("Your session has expired. Please log in again.");
    }
    if (res.status === 403 && !data?.detail) throw new Error("403 Forbidden: you don't have permission.");

    const validation = data?.errors && Object.values(data.errors).flat().join(" ");
    throw new Error(data?.detail || validation || data?.title || `Request failed (${res.status})`);
  }
  return data;
}

// Which form of the logged-out screen is visible: "login", "email" (step 1) or "register" (step 2)
function showForm(name) {
  $("login-form").hidden = name !== "login";
  $("email-form").hidden = name !== "email";
  $("register-form").hidden = name !== "register";
  $("tab-login").classList.toggle("active", name === "login");
  $("tab-register").classList.toggle("active", name !== "login");
}

function render(user) {
  $("guest").hidden = !!user;
  $("user").hidden = !user;
  $("delete-form").hidden = true;
  if (user) {
    $("u-name").textContent = user.name;
    $("u-email").textContent = user.email;
    $("u-role").textContent = user.role;
  } else {
    showForm("login");
  }
}

async function loadMe() {
  try { render(await api("/api/account/me")); }
  catch { render(null); }   // not logged in, or the session expired
}

// Tabs
$("tab-login").onclick = () => { showForm("login"); show(""); };
$("tab-register").onclick = () => { showForm(pendingEmail ? "register" : "email"); show(""); };

// Login
$("login-form").onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api("/api/auth/login", "POST", Object.fromEntries(new FormData(e.target)));  // server sets the cookie
    e.target.reset();
    show("Welcome!");
    await loadMe();
  } catch (err) { show(err.message, true); }
};

// Register, step 1: ask the server to e-mail a code
async function requestCode(email) {
  const data = await api("/api/auth/send-code", "POST", { email });
  pendingEmail = email;
  $("code-hint").textContent = `Enter the 6-digit code sent to ${email}. It expires in 10 minutes.`;
  show(data.message);
}

$("email-form").onsubmit = async (e) => {
  e.preventDefault();
  try {
    await requestCode(e.target.elements.email.value.trim().toLowerCase());
    showForm("register");
    $("register-form").elements.code.focus();
  } catch (err) { show(err.message, true); }
};

// Register, step 2: code + name + password -> the server creates the account and logs you in
$("register-form").onsubmit = async (e) => {
  e.preventDefault();
  const f = e.target.elements;
  try {
    await api("/api/auth/register", "POST", {
      email: pendingEmail,
      code: f.code.value.trim(),
      name: f.name.value,
      password: f.password.value
    });
    e.target.reset();
    $("email-form").reset();
    pendingEmail = "";
    show("Email confirmed. Welcome!");
    await loadMe();
  } catch (err) { show(err.message, true); }
};

$("btn-resend").onclick = async () => {
  try { await requestCode(pendingEmail); }
  catch (err) { show(err.message, true); }
};

$("btn-change-email").onclick = () => {
  pendingEmail = "";
  $("register-form").reset();
  showForm("email");
  show("");
};

// Logout is a server call: only the server can end the session and remove the HttpOnly cookie
$("btn-logout").onclick = async () => {
  try { await api("/api/auth/logout", "POST"); } catch { /* already logged out */ }
  render(null);
  show("Logged out.");
};

// Delete account: ask for the password again, the server verifies it
$("btn-delete").onclick = () => { $("delete-form").hidden = false; $("delete-form").elements.password.focus(); };
$("btn-delete-cancel").onclick = () => { $("delete-form").reset(); $("delete-form").hidden = true; };

$("delete-form").onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api("/api/account", "DELETE", { password: e.target.elements.password.value });
    e.target.reset();
    render(null);
    show("Account deleted.");
  } catch (err) { show(err.message, true); }
};

$("btn-admin").onclick = async () => {
  try { show((await api("/api/account/admin-only")).message); }
  catch (err) { show(err.message, true); }
};

loadMe();
