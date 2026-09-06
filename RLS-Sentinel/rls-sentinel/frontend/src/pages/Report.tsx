import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { FindingCard } from "../components/FindingCard";
import { ApiError, getScan, reportJsonUrl, type ScanStatusResponse } from "../lib/api";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const POLL_INTERVAL_MS = 1500;

export function Report() {
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<ScanStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;

    async function poll() {
      try {
        const data = await getScan(scanId!);
        if (cancelled) return;
        setScan(data);
        if (data.status === "pending" || data.status === "running") {
          timerRef.current = window.setTimeout(poll, POLL_INTERVAL_MS);
        }
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "Failed to load scan.");
      }
    }

    poll();
    return () => {
      cancelled = true;
      if (timerRef.current) window.clearTimeout(timerRef.current);
    };
  }, [scanId]);

  if (error) {
    return (
      <div className="mx-auto max-w-2xl p-6 text-center">
        <p className="text-red-600">{error}</p>
        <Link to="/" className="mt-4 inline-block text-[#d97757] underline">
          Back to scan form
        </Link>
      </div>
    );
  }

  if (!scan) {
    return <div className="mx-auto max-w-2xl p-6 text-center text-[#6b6a63]">Loading...</div>;
  }

  const isActive = scan.status === "pending" || scan.status === "running";
  const sorted = [...scan.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );

  return (
    <div className="mx-auto max-w-3xl p-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold" style={{ fontFamily: "Poppins, sans-serif" }}>
          Scan Report
        </h1>
        <p className="text-sm text-[#6b6a63]">{scan.target_url}</p>
      </div>

      {isActive && (
        <div className="mb-6 rounded-md border border-[#e5e3da] bg-white p-4 text-sm">
          Scanning in progress ({scan.status})... this page updates automatically.
        </div>
      )}

      {scan.status === "failed" && (
        <div className="mb-6 rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          Scan failed: {scan.error_message ?? "unknown error"}
        </div>
      )}

      {scan.status === "complete" && (
        <div className="mb-6 flex items-center justify-between">
          <p className="text-sm font-semibold">
            {scan.findings_count} finding{scan.findings_count === 1 ? "" : "s"}
          </p>
          <a
            href={reportJsonUrl(scan.scan_id)}
            target="_blank"
            rel="noreferrer"
            className="text-sm text-[#d97757] underline"
          >
            View raw report.json
          </a>
        </div>
      )}

      {scan.status === "complete" && scan.findings.length === 0 && (
        <p className="text-sm text-[#6b6a63]">
          No anonymous access issues found. Nice work.
        </p>
      )}

      <div className="flex flex-col gap-4">
        {sorted.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </div>

      <Link to="/" className="mt-8 inline-block text-sm text-[#d97757] underline">
        Run another scan
      </Link>
    </div>
  );
}
