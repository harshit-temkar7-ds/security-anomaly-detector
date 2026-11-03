import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("alert and user rows expose real, labelled buttons", () => {
  const alerts = source("../src/components/AlertsPanel.tsx");
  const users = source("../src/components/UsersPanel.tsx");
  assert.match(alerts, /<button className="table-action" aria-label=\{`Open alert row/);
  assert.match(users, /<button className="table-action" aria-label=\{`View profile for/);
  assert.doesNotMatch(alerts, /<tr[^>]*onClick=/);
  assert.doesNotMatch(users, /<tr[^>]*onClick=/);
});

test("empty alerts explain the active status filter", () => {
  const alerts = source("../src/components/AlertsPanel.tsx");
  assert.match(alerts, /No alerts with status '\$\{statusLabel\(f\.status\)\.toLowerCase\(\)\}' yet\./);
  assert.match(alerts, /Open an alert and change its status, or set Status to All\./);
  assert.match(alerts, /No alerts match these filters\. Try setting Status to All/);
});

test("report preview exposes progress, cancellation, and a safe failure reason", () => {
  const panel = source("../src/components/ReportPanel.tsx");
  const api = source("../src/api.ts");
  assert.match(panel, /Generating…/);
  assert.match(panel, /controller\.current\?\.abort\(\)/);
  assert.match(panel, /LLM summary could not be generated; showing the offline template report\./);
  assert.match(api, /signal\?: AbortSignal/);
  assert.match(api, /X-LLM-Reason/);
});

test("report explains when the optional LLM is unavailable", () => {
  const panel = source("../src/components/ReportPanel.tsx");
  assert.match(panel, /Unavailable: no LLM key configured\. The offline template report is used\./);
  assert.match(panel, /disabled={!config\?\.llm_available}/);
});

test("async tabs provide loading status and keep empty/error states", () => {
  for (const [path, loading, empty] of [
    ["../src/components/AlertsPanel.tsx", "Loading alerts", "No alerts match"],
    ["../src/components/UsersPanel.tsx", "Loading users", "No users match"],
    ["../src/components/HistoryPanel.tsx", "Loading scan history", "No saved scans yet"],
    ["../src/components/ThresholdPanel.tsx", "Updating threshold preview", "No threshold preview is available"],
  ]) {
    const text = source(path);
    assert.ok(text.includes(loading), `${path} should show loading`);
    assert.ok(text.includes(empty), `${path} should explain empty or current results`);
    assert.match(text, /role="alert"/);
  }
});
