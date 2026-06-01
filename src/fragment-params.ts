const paramNames = {
  pipingServerUrl: "server",
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

export function getConfiguredUrl({ pipingServerUrl, sshHost, sshPort, sshUsername, sshPassword, autoConnect }: SetFragmentParams): string {
  const searchParams = new URLSearchParams();
  if (pipingServerUrl !== undefined) {
    searchParams.set(paramNames.pipingServerUrl, pipingServerUrl);
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
