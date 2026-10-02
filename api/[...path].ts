/**
 * Vercel Serverless Function Proxy for the 'app' service.
 * Forwards requests from public /api/* to the internal 'network-monitor' service
 * using the injected service binding NETWORK_MONITOR_URL.
 */

export default async function handler(req: any, res: any) {
  const backendBaseUrl = process.env.NETWORK_MONITOR_URL;

  if (!backendBaseUrl) {
    return res.status(502).json({
      error: "Internal service binding NETWORK_MONITOR_URL is not configured."
    });
  }

  // Construct target URL using the bound base URL
  // e.g. new URL('/api/stats', process.env.NETWORK_MONITOR_URL)
  const targetUrl = new URL(req.url || "", backendBaseUrl);

  try {
    const headers: Record<string, string> = {};
    if (req.headers) {
      for (const [key, value] of Object.entries(req.headers)) {
        if (typeof value === "string" && key.toLowerCase() !== "host") {
          headers[key] = value;
        }
      }
    }

    const fetchOptions: RequestInit = {
      method: req.method || "GET",
      headers
    };

    if (req.method !== "GET" && req.method !== "HEAD" && req.body) {
      fetchOptions.body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
    }

    const backendResponse = await fetch(targetUrl.toString(), fetchOptions);
    const contentType = backendResponse.headers.get("content-type") || "";

    res.status(backendResponse.status);
    if (contentType) {
      res.setHeader("Content-Type", contentType);
    }

    if (contentType.includes("application/json")) {
      const jsonData = await backendResponse.json();
      return res.json(jsonData);
    } else {
      const textData = await backendResponse.text();
      return res.send(textData);
    }
  } catch (error: any) {
    return res.status(502).json({
      error: "Failed to connect to internal network-monitor service",
      details: error?.message || String(error)
    });
  }
}
