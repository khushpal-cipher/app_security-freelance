import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, startScan } from "../lib/api";

export function ScanForm() {
  const [targetUrl, setTargetUrl] = useState("");
  const [anonKey, setAnonKey] = useState("");
  const [tableNames, setTableNames] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!authorized) {
      setError("You must confirm you own or have permission to scan this project.");
      return;
    }

    setSubmitting(true);
    try {
      const tables = tableNames
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      const { scan_id } = await startScan(targetUrl.trim(), anonKey.trim(), tables);
      navigate(`/report/${scan_id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not start scan.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="mx-auto w-full max-w-lg rounded-xl border border-[#e5e3da] bg-white p-6 shadow-sm"
    >
      <div className="mb-4">
        <label htmlFor="target_url" className="mb-1 block text-sm font-semibold">
          Supabase Project URL
        </label>
        <input
          id="target_url"
          type="url"
          required
          placeholder="https://abcdefgh.supabase.co"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className="w-full rounded-md border border-[#e5e3da] px-3 py-2 text-sm focus:border-[#d97757] focus:outline-none"
        />
      </div>

      <div className="mb-4">
        <label htmlFor="anon_key" className="mb-1 block text-sm font-semibold">
          Anon / Public API Key
        </label>
        <input
          id="anon_key"
          type="password"
          required
          placeholder="eyJhbGciOi..."
          value={anonKey}
          onChange={(e) => setAnonKey(e.target.value)}
          className="w-full rounded-md border border-[#e5e3da] px-3 py-2 text-sm focus:border-[#d97757] focus:outline-none"
        />
        <p className="mt-1 text-xs text-[#6b6a63]">
          Never paste your <code>service_role</code> key here — anon/public only.
        </p>
      </div>

      <div className="mb-4">
        <label htmlFor="table_names" className="mb-1 block text-sm font-semibold">
          Table Names (optional)
        </label>
        <input
          id="table_names"
          type="text"
          placeholder="customers, blog_posts, internal_notes"
          value={tableNames}
          onChange={(e) => setTableNames(e.target.value)}
          className="w-full rounded-md border border-[#e5e3da] px-3 py-2 text-sm focus:border-[#d97757] focus:outline-none"
        />
        <p className="mt-1 text-xs text-[#6b6a63]">
          Comma-separated. Some Supabase projects block anon-key auto-discovery
          of tables — if the scan fails with a schema discovery error, list
          your tables here.
        </p>
      </div>

      <label className="mb-4 flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          checked={authorized}
          onChange={(e) => setAuthorized(e.target.checked)}
          className="mt-0.5"
        />
        <span>I own this Supabase project, or have explicit permission to scan it.</span>
      </label>

      {error && <p className="mb-4 text-sm text-red-600">{error}</p>}

      <button
        type="submit"
        disabled={submitting}
        className="w-full rounded-md bg-[#d97757] px-4 py-2 font-semibold text-white transition hover:opacity-90 disabled:opacity-50"
      >
        {submitting ? "Starting scan..." : "Run Scan"}
      </button>
    </form>
  );
}
