// SPA hardened control bundle (no secret, no decoys, no endpoints).
// Same SPA structure but contains only benign config. Alpha must probe this
// and find ZERO credentials (true negative for the FP gate).
const config = {
  appName: "Acme Internal Console",
  version: "1.0.0",
  baseURL: "/api/v1",
};

async function loadUsers() {
  const r = await fetch("/api/v1/users");
  return r.json();
}

document.getElementById("root").textContent = "Acme Internal Console ready";
export { loadUsers };
