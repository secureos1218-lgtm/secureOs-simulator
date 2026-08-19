// Resolve Backend Base URL:
// 1. Uses VITE_BACKEND_URL set in Vercel environment variables
// 2. Falls back to window.location.origin if served directly by Flask
// 3. Defaults to http://127.0.0.1:8000 during local Vite development
const getBackendUrl = (): string => {
  if (import.meta.env.VITE_BACKEND_URL) {
    return import.meta.env.VITE_BACKEND_URL.replace(/\/$/, "");
  }
  if (typeof window !== "undefined" && window.location.hostname !== "localhost") {
    return window.location.origin;
  }
  return "http://127.0.0.1:8000";
};

export const API_BASE = getBackendUrl();

// Dynamically construct secure WebSocket base URL (wss:// for HTTPS, ws:// for HTTP)
export const WS_BASE = API_BASE.replace(/^https:\/\//i, "wss://").replace(/^http:\/\//i, "ws://");

/**
 * Universal VAPT Report Exporter (HTML / Markdown)
 */
export async function exportReport(tool: string, data: any, format: "html" | "markdown" = "html") {
  try {
    const res = await fetch(`${API_BASE}/api/reports/export-universal`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tool, data, format }),
    });

    if (!res.ok) {
      throw new Error(`Failed to generate report (Status: ${res.status})`);
    }

    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `SecurOS_${tool}_Report.${format === "html" ? "html" : "md"}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (err: any) {
    console.error("[!] Report Export Error:", err);
    alert(`Failed to export ${tool} report: ${err.message}`);
  }
}

/**
 * JARVIS Threat Copilot Streaming SSE API
 */
export async function streamJarvis(
  prompt: string,
  contextData: any,
  onToken: (chunk: string) => void,
  onDone?: () => void
) {
  try {
    const response = await fetch(`${API_BASE}/api/jarvis/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt, context: contextData }),
    });

    if (!response.ok) {
      throw new Error(`HTTP Error ${response.status}: Failed to reach JARVIS engine`);
    }

    const reader = response.body?.getReader();
    const decoder = new TextDecoder();
    if (!reader) return;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      onToken(decoder.decode(value));
    }
  } catch (err: any) {
    onToken(`\n[!] Stream Connection Error: ${err.message}`);
  } finally {
    if (onDone) onDone();
  }
}
