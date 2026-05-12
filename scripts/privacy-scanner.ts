#!/usr/bin/env bun
/**
 * Privacy scanner subprocess — loads openai/privacy-filter once, then
 * reads lines of text from stdin and writes JSON findings to stdout.
 *
 * Protocol:
 *   stdin  → one line of text per request
 *   stdout → JSON array of { kind, start, end, value } per response
 *
 * The model stays warm across requests; only the first request pays
 * the download / load cost.
 */

import { pipeline } from "@huggingface/transformers";

const MODEL_ID = "openai/privacy-filter";

// Map model labels → AgentGate finding kinds.
const LABEL_TO_KIND: Record<string, string> = {
  secret: "secret",
  account_number: "account_number",
  private_address: "private_address",
  private_email: "private_email",
  private_person: "private_person",
  private_phone: "private_phone",
  private_url: "private_url",
  private_date: "private_date",
};

interface Finding {
  kind: string;
  start: number;
  end: number;
  value: string;
}

async function main() {
  const pipe = await pipeline("token-classification", MODEL_ID, {
    dtype: "fp32",
  });

  process.stdin.setEncoding("utf-8");

  let buffer = "";
  process.stdin.on("data", async (chunk: string) => {
    buffer += chunk;
    let newlineIdx: number;
    while ((newlineIdx = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, newlineIdx).trimEnd();
      buffer = buffer.slice(newlineIdx + 1);
      if (line === "") {
        process.stdout.write("[]\n");
        continue;
      }
      const findings = await classify(pipe, line);
      process.stdout.write(JSON.stringify(findings) + "\n");
    }
  });
}

async function classify(pipe: any, text: string): Promise<Finding[]> {
  const tokens = await pipe(text, { aggregation_strategy: "simple" });

  const findings: Finding[] = [];
  for (const tok of tokens) {
    const group = tok.entity_group as string;
    const kind = LABEL_TO_KIND[group];
    if (!kind) continue;

    findings.push({
      kind,
      start: tok.start,
      end: tok.end,
      value: text.slice(tok.start, tok.end),
    });
  }
  return findings;
}

main().catch((err) => {
  process.stderr.write(`privacy-scanner: ${err}\n`);
  process.exit(1);
});
