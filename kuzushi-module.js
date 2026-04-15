/**
 * Kuzushi module wrapper for augur (IRIS neuro-symbolic SAST).
 * Exposes the IRIS two-phase pipeline as ModuleTools.
 */

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function loadWorkflow() {
  try {
    return readFileSync(join(__dirname, "WORKFLOW.md"), "utf-8");
  } catch {
    return "";
  }
}

function loadSkill() {
  try {
    return readFileSync(join(__dirname, "adapters", "claude-code", "SKILL.md"), "utf-8");
  } catch {
    return "";
  }
}

const workflow = loadWorkflow();
const skill = loadSkill();

export default {
  id: "augur",
  displayName: "Augur IRIS Taint Analysis",
  category: "offense",
  version: "0.3.0",
  description:
    "Neuro-symbolic SAST using IRIS methodology — " +
    "LLM-driven CodeQL taint analysis with human review checkpoint.",
  tools: [
    {
      name: "augur:taint",
      description:
        "Run the full IRIS taint analysis pipeline on a CodeQL database. " +
        "Phase 1: Extract sources/sinks, LLM-label them. " +
        "Phase 2: Generate custom CodeQL queries, run analysis, report findings.",
      inputSchema: {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          dbPath: { type: "string", description: "Path to the CodeQL database." },
          passes: { type: "string", description: "Comma-separated CWE pass numbers (e.g. 1,5,7)." },
        },
        required: ["target"],
      },
      headless: true,
      async execute(input, ctx) {
        const params = input ?? {};
        const target = params.target ?? ctx.target ?? ".";
        const dbPath = params.dbPath ?? "";
        const passes = params.passes ?? "all";

        const prompt = [
          skill,
          "",
          `Run augur/IRIS on target: ${target}`,
          dbPath ? `CodeQL database: ${dbPath}` : "",
          `Passes: ${passes}`,
          "",
          "Follow the WORKFLOW.md pipeline exactly.",
          "",
          workflow,
        ].filter(Boolean).join("\n");

        try {
          let text = "";
          for await (const msg of ctx.runtime.query(prompt, {
            systemPrompt: "You are running the IRIS neuro-symbolic SAST pipeline.",
            tools: ["Read", "Glob", "Grep", "Bash"],
          })) {
            if (msg.type === "result") text = msg.text ?? text;
            else if (msg.type === "assistant" && msg.content) {
              for (const block of msg.content) {
                if (block.type === "text") text += block.text;
              }
            }
          }
          return { ok: true, output: text || "IRIS analysis complete." };
        } catch (err) {
          return { ok: false, output: `Augur error: ${err.message ?? err}` };
        }
      },
    },
    {
      name: "augur:label",
      description:
        "Run only Phase 1 of IRIS — extract and LLM-label sources/sinks. " +
        "Stops at the human review checkpoint before generating queries.",
      inputSchema: {
        type: "object",
        properties: {
          target: { type: "string", description: "Path to the repository." },
          dbPath: { type: "string", description: "Path to the CodeQL database." },
        },
        required: ["target"],
      },
      headless: true,
      async execute(input, ctx) {
        const params = input ?? {};
        const target = params.target ?? ctx.target ?? ".";

        const prompt = [
          skill,
          "",
          `Run augur/IRIS Phase 1 only (extract + label) on target: ${target}`,
          params.dbPath ? `CodeQL database: ${params.dbPath}` : "",
          "",
          "Stop at the checkpoint after labeling. Do NOT proceed to Phase 2.",
        ].filter(Boolean).join("\n");

        try {
          let text = "";
          for await (const msg of ctx.runtime.query(prompt, {
            systemPrompt: "You are running IRIS Phase 1: extraction and labeling.",
            tools: ["Read", "Glob", "Grep", "Bash"],
          })) {
            if (msg.type === "result") text = msg.text ?? text;
            else if (msg.type === "assistant" && msg.content) {
              for (const block of msg.content) {
                if (block.type === "text") text += block.text;
              }
            }
          }
          return { ok: true, output: text || "Labeling complete. Review labels before proceeding." };
        } catch (err) {
          return { ok: false, output: `Augur error: ${err.message ?? err}` };
        }
      },
    },
  ],
};
