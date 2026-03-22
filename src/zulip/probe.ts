import { fetchWithSsrFGuard } from "openclaw/plugin-sdk";
import { normalizeZulipBaseUrl, readZulipError, type ZulipUser } from "./client.js";

export type ZulipProbe = {
  ok: boolean;
  baseUrl?: string;
  bot?: ZulipUser;
  error?: string;
};

export type TlsOptions = {
  caCertificate?: string;  // PEM-encoded CA certificate (future: not yet implemented)
  rejectUnauthorized?: boolean;  // Set to false for self-signed certs (insecure)
};

export async function probeZulip(
  baseUrl: string,
  email: string,
  apiKey: string,
  timeoutMs?: number,
  tlsOptions?: TlsOptions,
): Promise<ZulipProbe> {
  const normalized = normalizeZulipBaseUrl(baseUrl);
  if (!normalized) {
    return { ok: false, error: "invalid baseUrl" };
  }

  // Handle TLS options
  // WARNING: Setting rejectUnauthorized to false is insecure - only use for development/self-signed certs
  const previousTlsSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  if (tlsOptions?.rejectUnauthorized === false) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }

  const controller = new AbortController();
  const timeout = timeoutMs ? setTimeout(() => controller.abort(), Math.max(timeoutMs, 500)) : null;

  try {
    const authHeader = Buffer.from(`${email}:${apiKey}`).toString("base64");
    const { response: res, release } = await fetchWithSsrFGuard({
      url: `${normalized}/api/v1/users/me`,
      init: {
        headers: {
          Authorization: `Basic ${authHeader}`,
        },
        signal: controller.signal,
      },
      policy: { allowPrivateNetwork: true },
    });
    try {
      if (!res.ok) {
        const detail = await readZulipError(res);
        return { ok: false, error: detail || res.statusText };
      }
      const data = (await res.json()) as {
        result?: string;
        msg?: string;
        user_id?: number;
        email?: string;
        full_name?: string;
      };
      if (data.result && data.result !== "success") {
        return { ok: false, error: data.msg || "Zulip API error" };
      }
      return {
        ok: true,
        baseUrl: normalized,
        bot: {
          id: String(data.user_id ?? ""),
          email: data.email ?? null,
          full_name: data.full_name ?? null,
        },
      };
    } finally {
      await release();
    }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
    // Restore previous TLS setting
    if (previousTlsSetting === undefined) {
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    } else {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousTlsSetting;
    }
  }
}