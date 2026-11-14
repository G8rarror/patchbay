import type { AcpPermissionRequest, AcpToolCall } from "../lib/ipc.ts";

type PatchbayMeta = { workerGitPrompt?: boolean; command?: string; cwd?: string };

function commandOf(tc: AcpToolCall): string | null {
  const raw = (tc.rawInput ?? {}) as Record<string, unknown>;
  for (const k of ["command", "cmd"]) {
    const v = raw[k];
    if (typeof v === "string" && v.trim()) return v.trim();
    if (Array.isArray(v) && v.length) return v.filter((x) => typeof x === "string").join(" ");
  }
  return null;
}

/** Promote `_meta.patchbay` the same way `mergeToolCall` does (store.ts), without importing the store. */
function withPatchbayMeta(tc: AcpToolCall): AcpToolCall & { _patchbay?: PatchbayMeta } {
  const meta = (tc as AcpToolCall & { _meta?: { patchbay?: PatchbayMeta } })._meta?.patchbay;
  if (!meta) return tc;
  return {
    ...tc,
    patchbayCommand: tc.patchbayCommand ?? meta.command,
    patchbayCwd: tc.patchbayCwd ?? meta.cwd,
    workerGitPrompt: tc.workerGitPrompt || !!meta.workerGitPrompt,
    _patchbay: meta,
  };
}

/**
 * Pure view of a permission request for PermissionCard and selftests.
 * Worker git (C2, ToolCallCard.tsx ~450): never offer allow_always / Patchbay Always rule.
 */
export function permissionCardView(
  request: AcpPermissionRequest,
  live?: AcpToolCall,
): {
  workerGit: boolean;
  actions: { kind: string; optionId: string; name: string }[];
  command: string | null;
  cwd: string | null;
  askReason: string | null;
  showAlwaysRule: boolean;
} {
  const tc = withPatchbayMeta({ ...(live ?? { toolCallId: request.toolCall.toolCallId }), ...request.toolCall });
  const reqMeta =
    (request.toolCall as AcpToolCall & { _meta?: { patchbay?: PatchbayMeta } })._meta?.patchbay ?? tc._patchbay;
  const workerGit = !!(tc.workerGitPrompt || reqMeta?.workerGitPrompt);
  const command =
    tc.patchbayCommand?.trim() ||
    reqMeta?.command?.trim() ||
    (tc.kind === "execute" ? commandOf(tc) : null);
  const cwd = (tc.patchbayCwd ?? reqMeta?.cwd ?? "").trim() || null;
  const allows = request.options
    .filter((o) => o.kind === "allow_once" || (!workerGit && !o.kind?.startsWith("reject")))
    .filter((o) => !(workerGit && o.kind === "allow_always"))
    .sort((x, y) => Number(x.kind !== "allow_once") - Number(y.kind !== "allow_once"));
  const rejects = request.options.filter((o) => o.kind?.startsWith("reject") && o.kind !== "reject_always");
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
    askReason,
    showAlwaysRule: !workerGit && allowOnce,
  };
}
