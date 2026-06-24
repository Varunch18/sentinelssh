/* Thin REST client. Unwraps the {success,data} envelope and redirects to the
   login page on 401 (session expired / not authenticated). */
const API = (() => {
  async function request(path, options = {}) {
    const res = await fetch('/api' + path, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (res.status === 401) {
      window.location.href = '/login';
      throw new Error('unauthorized');
    }
    const json = await res.json().catch(() => ({}));
    if (!res.ok || json.success === false) {
      const msg = (json.error && json.error.message) || ('HTTP ' + res.status);
      throw new Error(msg);
    }
    return json;
  }

  return {
    async get(path) { return (await request(path)).data; },
    async getFull(path) { return await request(path); },
    async post(path, body) {
      return (await request(path, { method: 'POST', body: JSON.stringify(body || {}) })).data;
    },
  };
})();
