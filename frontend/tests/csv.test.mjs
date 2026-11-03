import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const source = await readFile(new URL("../src/csv.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
});
const { toCsv } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);

test("CSV export prefixes formula-like uploaded column headers", () => {
  const csv = toCsv([{
    row: 1, is_anomaly: false, anomaly_score: 0, rule_flag: false, review_reason: "ok",
    "=1+1": "value",
  }], ["=1+1"]);

  assert.equal(csv, "'=1+1\nvalue");
});

test("CSV export quotes sanitized headers that contain delimiters", () => {
  const csv = toCsv([{
    row: 1, is_anomaly: false, anomaly_score: 0, rule_flag: false, review_reason: "ok",
    '=@SUM("x,y")': "value",
  }], ['=@SUM("x,y")']);

  assert.equal(csv.split("\n")[0], `"'=@SUM(""x,y"")"`);
});
