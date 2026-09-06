export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AccessType = "read" | "write" | "delete";
export type ScanStatus = "pending" | "running" | "complete" | "failed";

export interface Finding {
  id: string;
  table_name: string;
  access_type: AccessType;
  severity: Severity;
  description: string;
  fix_prompt: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: ScanStatus;
  target_url: string;
  findings_count: number;
  error_message: string | null;
  findings: Finding[];
}

const API_BASE = "/api";

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function parseErrorDetail(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      return body.detail.map((d: { msg?: string }) => d.msg ?? String(d)).join("; ");
    }
    return response.statusText;
  } catch {
    return response.statusText;
  }
}

export async function startScan(
  targetUrl: string,
  anonKey: string,
  tableNames?: string[],
): Promise<{ scan_id: string }> {
  const response = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target_url: targetUrl,
      anon_key: anonKey,
      authorized: true,
      table_names: tableNames && tableNames.length > 0 ? tableNames : null,
    }),
  });
  if (!response.ok) {
    throw new ApiError(await parseErrorDetail(response), response.status);
  }
  return response.json();
}

export async function getScan(scanId: string): Promise<ScanStatusResponse> {
  const response = await fetch(`${API_BASE}/scan/${scanId}`);
  if (!response.ok) {
    throw new ApiError(await parseErrorDetail(response), response.status);
  }
  return response.json();
}

export function reportJsonUrl(scanId: string): string {
  return `${API_BASE}/scan/${scanId}/report.json`;
}
