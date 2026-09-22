// dashboard/src/api/client.js

import axios from "axios";

const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:8000";

export const api = axios.create({ baseURL: API_BASE });

export const fetchPipeline = (payload) =>
  api.post("/v1/pipeline", payload).then((r) => r.data);

export const fetchAuditLogs = (params = {}) =>
  api.get("/v1/audit/logs", { params }).then((r) => r.data);

export const fetchStats = (window = "24h") =>
  api.get("/v1/audit/stats", { params: { window } }).then((r) => r.data);

export const fetchAlerts = () =>
  api.get("/v1/alerts").then((r) => r.data);