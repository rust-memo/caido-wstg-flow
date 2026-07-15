export function statusLabel(value: string): string {
  return value.replaceAll("_", " ").toLowerCase();
}

export function formatDate(value: string): string {
  return new Date(value).toLocaleString();
}

export function safeMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

export function splitList(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[,\r\n]+/)
        .map((entry) => entry.trim().toLowerCase())
        .filter(Boolean),
    ),
  ];
}
