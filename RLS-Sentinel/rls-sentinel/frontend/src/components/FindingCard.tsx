import { useState } from "react";
import type { AccessType, Finding, Severity } from "../lib/api";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-400 text-[#141413]",
  low: "bg-blue-400 text-white",
  info: "bg-gray-300 text-[#141413]",
};

const ATTACKER_SENTENCE: Record<AccessType, string> = {
  read: "read every row in this table without logging in, using only the public anon key.",
  write: "possibly insert, modify, or delete rows in this table without logging in — this was not directly tested, only inferred from readable data.",
  delete: "delete rows from this table without logging in, using only the public anon key.",
};

function legacyCopy(text: string): boolean {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(textarea);
  return ok;
}

export function FindingCard({ finding }: { finding: Finding }) {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  async function handleCopy() {
    let ok = false;
    try {
      await navigator.clipboard.writeText(finding.fix_prompt);
      ok = true;
    } catch {
      ok = legacyCopy(finding.fix_prompt);
    }
    setCopyState(ok ? "copied" : "failed");
    setTimeout(() => setCopyState("idle"), 2000);
  }

  return (
    <div className="rounded-lg border border-[#e5e3da] bg-white p-5 shadow-sm">
      <div className="flex items-start justify-between gap-4">
        <div>
          <span
            className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_STYLES[finding.severity]}`}
          >
            {finding.severity}
          </span>
          <h3
            className="mt-2 text-lg font-semibold"
            style={{ fontFamily: "Poppins, sans-serif" }}
          >
            {finding.table_name}{" "}
            <span className="font-normal text-[#6b6a63]">— {finding.access_type}</span>
          </h3>
        </div>
      </div>

      <p className="mt-3 text-sm leading-relaxed" style={{ fontFamily: "Lora, serif" }}>
        {finding.description}
      </p>

      <p className="mt-2 text-sm italic leading-relaxed text-[#6b6a63]" style={{ fontFamily: "Lora, serif" }}>
        An attacker could {ATTACKER_SENTENCE[finding.access_type]}
      </p>

      <div className="mt-4">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wide text-[#6b6a63]">
            Fix prompt
          </span>
          <button
            onClick={handleCopy}
            className="rounded-md bg-[#d97757] px-3 py-1 text-xs font-semibold text-white transition hover:opacity-90"
          >
            {copyState === "copied" ? "Copied!" : copyState === "failed" ? "Copy failed — select manually" : "Copy"}
          </button>
        </div>
        <pre className="mt-1 max-h-48 overflow-auto rounded-md bg-[#141413] p-3 text-xs text-[#faf9f5]">
          {finding.fix_prompt}
        </pre>
      </div>
    </div>
  );
}
