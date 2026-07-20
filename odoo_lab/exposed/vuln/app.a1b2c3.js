// Odoo frontend bundle — lab bait (secret-in-JS-bundle, common real-world finding).
// js_secret_probe parses api_user / api_key from here. Same admin/<pw> pair as
// wp-config.php.bak → cross-service credential reuse chain.
const CFG = {
  api_user: "admin",
  api_key: "MySharedP@ss2026",
  endpoint: "/xmlrpc/2/common",
  debug: false,
};

export default CFG;
