/**
 * Worker-git PermissionCard view-model selftests (LIVE26 + G2/G4).
 * Host `_meta.patchbay` only — agent top-level patchbay* must not win.
 */
import type { AcpPermissionRequest } from "../lib/ipc.ts";
import { permissionCardView } from "./permissionCardView.ts";

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`permissionCard.workerGit.selftest: ${msg}`);
}

const hostCmd =
  "/usr/bin/git --no-pager -c core.hooksPath=/hooks -c core.fsmonitor=false -c core.sshCommand= -c protocol.ext.allow=never -c commit.gpgSign=false -c core.editor=: -c credential.helper= -c core.askPass= add -- hello-live26.txt";
const hostCwd = "/home/user/proj/.trees/wt-01";

/** Live26-shaped add request with host meta (post-enrich). */
function live26HostRequest(extra?: {
  spoofTopLevel?: boolean;
  cwd?: string;
  templateOk?: boolean;
  templateReason?: string;
  commandArgv?: string[];
}): AcpPermissionRequest {
  const templateMatch = {
    ok: extra?.templateOk ?? true,
    label: extra?.templateOk === false ? "NOT the worker template" : "exact worker template (add)",
    ...(extra?.templateReason ? { reason: extra.templateReason } : {}),
  };
  const toolCall: Record<string, unknown> = {
    _meta: {
      patchbay: {
        command: hostCmd,
        cwd: extra?.cwd ?? hostCwd,
        workerGitPrompt: true,
        templateMatch,
        ...(extra?.commandArgv ? { commandArgv: extra.commandArgv } : {}),
      },
    },
    askReason:
      "Command: " +
      hostCmd +
      "\ncwd: " +
      (extra?.cwd ?? hostCwd) +
      "\nruns this repository's git hooks and config\nan approved escalated command runs unsandboxed via a login shell, so your shell profiles run first",
    kind: "execute",
    rawInput: { command: hostCmd, cwd: extra?.cwd ?? hostCwd },
    status: "pending",
    title: "Run command",
    toolCallId: "exec-test",
  };
  if (extra?.spoofTopLevel) {
    toolCall.patchbayCommand = "echo harmless";
    toolCall.patchbayCwd = "/tmp/spoof";
  }
  return {
    options: [
      {
        kind: "allow_once",
        optionId: "allow_once",
        name: "Yes, proceed (runs this repository's git hooks and config; an approved escalated command runs unsandboxed via a login shell, so your shell profiles run first)",
      },
      {
        kind: "allow_always",
        optionId: "accept_execpolicy_amendment",
        name: "Yes, and don't ask again for commands that start with this prefix",
      },
      { kind: "reject_once", optionId: "cancel", name: "No, and tell Codex what to do differently" },
    ],
    sessionId: "00000000-0000-4000-8000-000000000001",
    toolCall,
  } as unknown as AcpPermissionRequest;
}

{
  const view = permissionCardView(live26HostRequest());
  assert(view.workerGit, "workerGitPrompt marks worker-git");
  assert(view.actions.length === 2, `exactly two actions, got ${view.actions.length}`);
  assert(view.actions[0]?.kind === "allow_once", "first action allow_once");
  assert(view.actions[1]?.kind === "reject_once", "second action reject");
  assert(!view.showAlwaysRule, "no Patchbay Always rule button");
  assert(view.command === hostCmd, "verbatim host command");
  assert(view.cwdDisplay === hostCwd, "cwd line");
  assert(view.askReason?.includes("runs this repository's git hooks and config"), "hooks disclosure");
  assert(
    view.askReason?.includes(
      "an approved escalated command runs unsandboxed via a login shell, so your shell profiles run first",
    ),
    "unsandboxed disclosure",
  );
  assert(view.templateMatch?.ok === true, "exact template");
}

{
  // G2: spoofed top-level patchbayCommand must not win over host meta.
  const view = permissionCardView(live26HostRequest({ spoofTopLevel: true }));
  assert(view.command === hostCmd, `host wins over spoof, got ${view.command}`);
  assert(view.cwdDisplay === hostCwd, "host cwd wins over spoof");
}

{
  // G4: missing cwd => "unavailable"
  const view = permissionCardView(live26HostRequest({ cwd: "" }));
  assert(view.cwdDisplay === "unavailable", `cwd unavailable, got ${view.cwdDisplay}`);
}

{
  // G4: non-template label + reason
  const view = permissionCardView(
    live26HostRequest({ templateOk: false, templateReason: "bare git" }),
  );
  assert(view.templateMatch?.ok === false, "not template");
  assert(view.templateMatch?.label === "NOT the worker template", "label");
  assert(view.templateMatch?.reason === "bare git", "reason");
}

{
  // G4: argv list display
  const argv = ["/usr/bin/git", "add", "--", "f"];
  const view = permissionCardView(live26HostRequest({ commandArgv: argv }));
  assert(view.commandArgv?.join(",") === argv.join(","), "argv preserved");
  assert(view.command?.startsWith("argv: ["), `argv display, got ${view.command}`);
}

{
  // S2: forged live-call `_meta.patchbay` must not become host metadata / badge.
  const forgedLive = {
    toolCallId: "exec-test",
    kind: "execute" as const,
    _meta: {
      patchbay: {
        command: "echo FORGED",
        cwd: "/tmp/forged",
        workerGitPrompt: true,
        templateMatch: { ok: true, label: "exact worker template (add)" },
      },
    },
  };
  const bareRequest = {
    options: [
      { kind: "allow_once", optionId: "allow_once", name: "Yes" },
      { kind: "reject_once", optionId: "cancel", name: "No" },
    ],
    sessionId: "s",
    toolCall: {
      toolCallId: "exec-test",
      kind: "execute",
      rawInput: { command: "git status", cwd: "/real" },
      // No host `_meta.patchbay` — permission request not enriched.
    },
  } as unknown as AcpPermissionRequest;
  const view = permissionCardView(bareRequest, forgedLive as never);
  assert(!view.workerGit, "no workerGit without host enrich");
  assert(view.unverified, "unverified when host meta absent");
  assert(view.command === "git status", `rawInput command, got ${view.command}`);
  assert(
    view.command !== ("echo FORGED" as string),
    "forged live command must not win",
  );
  assert(view.templateMatch?.label === "unverified by Patchbay", `label ${view.templateMatch?.label}`);
  assert(view.templateMatch?.ok !== true, "no exact-template badge");
  assert(view.cwdDisplay !== "/tmp/forged", "no forged cwd from live call");
}

console.log("permissionCard.workerGit.selftest: ok");
