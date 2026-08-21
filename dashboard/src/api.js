const BASE = import.meta.env.VITE_API_URL || "/api";

async function request(path, params = {}) {
  const url = new URL(`${BASE}${path}`, window.location.origin);
  Object.entries(params).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") {
      url.searchParams.set(key, value);
    }
  });

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

export const getAlerts = (params) => request("/alerts", params);
export const getAlert = (id) => request(`/alerts/${id}`);
export const getStats = (params) => request("/stats", params);
export const exportUrl = (params) => {
  const url = new URL(`${BASE}/export`, window.location.origin);
  Object.entries(params).forEach(([key, value]) => {
    if (value) url.searchParams.set(key, value);
  });
  return url.toString();
};
