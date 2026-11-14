import type { AcpPermissionRequest, AcpToolCall } from "../lib/ipc.ts";

type TemplateMatch = { ok?: boolean; label?: string; reason?: string };
type PatchbayMeta = {
  workerGitPrompt?: boolean;
  command?: string;
  cwd?: string;
  commandArgv?: string[];
  templateMatch?: TemplateMatch;
};

/**
 * Pure view of a permission request for PermissionCard and selftests.
 * Worker git (C2 / G2): trust ONLY host `_meta.patchbay` — never agent top-level patchbay*.
 */
export function permissionCardView(
  request: AcpPermissionRequest,
  live?: AcpToolCall,
): {
  workerGit: boolean;
  actions: { kind: string; optionId: string; name: string }[];
  command: string | null;
  cwd: string | null;
  cwdDisplay: string | null;
  askReason: string | null;
  showAlwaysRule: boolean;
  templateMatch: TemplateMatch | null;
  commandArgv: string[] | null;
} {
  const tc = { ...(live ?? { toolCallId: request.toolCall.toolCallId }), ...request.toolCall } as AcpToolCall & {
    _meta?: { patchbay?: PatchbayMeta };
  };
  // Host metadata only (G2). Agent-supplied top-level patchbayCommand/patchbayCwd are ignored.
  const host = (request.toolCall as AcpToolCall & { _meta?: { patchbay?: PatchbayMeta } })._meta?.patchbay
    ?? tc._meta?.patchbay;
  const workerGit = !!host?.workerGitPrompt;
  let command: string | null = null;
  let commandArgv: string[] | null = null;
  if (host?.commandArgv && host.commandArgv.length) {
    commandArgv = host.commandArgv;
    command = `argv: [${host.commandArgv.map((a) => JSON.stringify(a)).join(", ")}]`;
  } else if (host?.command?.trim()) {
    command = host.command.trim();
  }
  const cwdRaw = host?.cwd;
  const cwd = typeof cwdRaw === "string" ? cwdRaw : null;
  const cwdDisplay = workerGit ? (cwd && cwd.trim() ? cwd.trim() : "unavailable") : cwd && cwd.trim() ? cwd.trim() : null;
  const allows = request.options
    .filter((o) => o.kind === "allow_once" || (!workerGit && !o.kind?.startsWith("reject")))
    .filter((o) => !(workerGit && o.kind === "allow_always"))
    .sort((x, y) => Number(x.kind !== "allow_once") - Number(y.kind !== "allow_once"));
  const rejects = request.options.filter((o) =>
    workerGit ? o.kind === "reject_once" : o.kind?.startsWith("reject") && o.kind !== "reject_always",
  );
  const actions = [...allows, ...rejects].map((o) => ({
    kind: o.kind ?? "",
    optionId: o.optionId,
    name: o.name ?? "",
  }));
  const allowOnce = request.options.some((o) => o.kind === "allow_once");
  const askReason = tc.askReason?.trim() || null;
  return {
    workerGit,
    actions,
    command,
    cwd,
    cwdDisplay,
    askReason,
    showAlwaysRule: !workerGit && allowOnce,
    templateMatch: host?.templateMatch ?? null,
    commandArgv,
  };
}
