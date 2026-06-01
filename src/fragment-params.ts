import {z} from "zod";

const headersType = z.array(z.tuple([z.string(), z.string()]));

const paramNames = {
  pipingServerUrl: "server",
  pipingServerHeaders: "headers",
  sshHost: "host",
  sshPort: "port",
  sshUsername: "user",
  sshPassword: "password",
  autoConnect: "auto_connect",
};

export const fragmentParams = {
  pipingServerUrl(): string | undefined {
    return parseFragmentParams().get(paramNames.pipingServerUrl) ?? undefined;
  },
  pipingServerHeaders(): Array<[string, string]> | undefined {
    const headersString = parseFragmentParams().get(paramNames.pipingServerHeaders);
    if (headersString === null) {
      return undefined;
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(decodeURIComponent(headersString));
    } catch {
      return undefined;
    }
    const parsed = headersType.safeParse(decoded);
    if (!parsed.success) {
      return undefined;
    }
    return parsed.data;
  },
  sshHost(): string | undefined {
    return parseFragmentParams().get(paramNames.sshHost) ?? undefined;
  },
  sshPort(): string | undefined {
    return parseFragmentParams().get(paramNames.sshPort) ?? undefined;
  },
  sshUsername(): string | undefined {
    return parseFragmentParams().get(paramNames.sshUsername) ?? undefined;
  },
  sshPassword(): string | undefined {
    return parseFragmentParams().get(paramNames.sshPassword) ?? undefined;
  },
  autoConnect(): boolean | undefined {
    const str = parseFragmentParams().get(paramNames.autoConnect);
    return str !== null && ["", "1", "true"].includes(str);
  }
};

type SetFragmentParams = { [K in keyof (typeof fragmentParams) ]: ReturnType<(typeof fragmentParams)[K]> }

export function getConfiguredUrl({ pipingServerUrl, pipingServerHeaders, sshHost, sshPort, sshUsername, sshPassword, autoConnect }: SetFragmentParams): string {
  const searchParams = new URLSearchParams();
  if (pipingServerUrl !== undefined) {
    searchParams.set(paramNames.pipingServerUrl, pipingServerUrl);
  }
  if (pipingServerHeaders !== undefined && pipingServerHeaders.length !== 0) {
    searchParams.set(paramNames.pipingServerHeaders, JSON.stringify(pipingServerHeaders));
  }
  if (sshHost !== undefined) {
    searchParams.set(paramNames.sshHost, sshHost);
  }
  if (sshPort !== undefined && sshPort !== "") {
    searchParams.set(paramNames.sshPort, sshPort);
  }
  if (sshUsername !== undefined) {
    searchParams.set(paramNames.sshUsername, sshUsername);
  }
  if (sshPassword !== undefined) {
    searchParams.set(paramNames.sshPassword, sshPassword);
  }
  if (autoConnect !== undefined && autoConnect) {
    searchParams.set(paramNames.autoConnect, "1");
  }
  const url = new URL(location.href);
  url.hash = `?${searchParams.toString()}`
  return url.href
    .replaceAll("%3A", ":")
    .replaceAll("%2F", "/");
}

function parseFragmentParams(): URLSearchParams {
  const url = new URL(`a://a${location.hash.substring(1)}`);
  return url.searchParams;
}
