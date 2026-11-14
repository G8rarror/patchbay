/**
 * LIVE26 UI evidence gap: PermissionCard for worker-git shows allow_once + reject only
 * (ToolCallCard.tsx ~450), never allow_always / Patchbay Always. Renders the view model from
 * the live26 raw permission request JSON.
 */
import type { AcpPermissionRequest } from "../lib/ipc.ts";
import { permissionCardView } from "./permissionCardView.ts";

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`permissionCard.workerGit.selftest: ${msg}`);
}

/** Live26 add prompt (fd96f0fe…), trimmed to the fields PermissionCard reads. */
const live26AddRequest = {
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
    {
      kind: "reject_once",
      optionId: "cancel",
      name: "No, and tell Codex what to do differently",
    },
  ],
  sessionId: "01a1daf8-ab7c-7f73-a056-021563552406",
  toolCall: {
    _meta: {
      patchbay: {
        command:
          "/usr/bin/git --no-pager -c core.hooksPath=/Users/dfrazer/patchbay-teams-data/teams-safe/476c429a-e307-448b-9012-36c8e68a770d/hooks -c core.fsmonitor=false -c core.sshCommand= -c protocol.ext.allow=never -c commit.gpgSign=false -c core.editor=: -c credential.helper= -c core.askPass= add -- hello-live26.txt PB_COMMIT_MSG",
        cwd: "/Users/dfrazer/patchbay-teams-data/proj-home/.trees/live26r93688-20261114-01",
        workerGitPrompt: true,
      },
    },
    askReason:
      "Command: /usr/bin/git --no-pager -c core.hooksPath=/Users/dfrazer/patchbay-teams-data/teams-safe/476c429a-e307-448b-9012-36c8e68a770d/hooks -c core.fsmonitor=false -c core.sshCommand= -c protocol.ext.allow=never -c commit.gpgSign=false -c core.editor=: -c credential.helper= -c core.askPass= add -- hello-live26.txt PB_COMMIT_MSG\ncwd: /Users/dfrazer/patchbay-teams-data/proj-home/.trees/live26r93688-20261114-01\nruns this repository's git hooks and config\nan approved escalated command runs unsandboxed via a login shell, so your shell profiles run first",
    kind: "execute",
    rawInput: {
      command:
        "/usr/bin/git --no-pager -c core.hooksPath=/Users/dfrazer/patchbay-teams-data/teams-safe/476c429a-e307-448b-9012-36c8e68a770d/hooks -c core.fsmonitor=false -c core.sshCommand= -c protocol.ext.allow=never -c commit.gpgSign=false -c core.editor=: -c credential.helper= -c core.askPass= add -- hello-live26.txt PB_COMMIT_MSG",
      cwd: "/Users/dfrazer/patchbay-teams-data/proj-home/.trees/live26r93688-20261114-01",
    },
    status: "pending",
    title: "Run command",
    toolCallId: "exec-d6a3295a-7be8-4c5c-b3a8-2df35d95fb71",
  },
} as unknown as AcpPermissionRequest;

const view = permissionCardView(live26AddRequest);

assert(view.workerGit, "workerGitPrompt marks worker-git");
assert(view.actions.length === 2, `exactly two actions, got ${view.actions.length}: ${JSON.stringify(view.actions)}`);
assert(view.actions[0]?.kind === "allow_once" && view.actions[0]?.optionId === "allow_once", "first action allow_once");
assert(view.actions[1]?.kind === "reject_once" && view.actions[1]?.optionId === "cancel", "second action reject");
assert(!view.showAlwaysRule, "no Patchbay Always rule button");
const expectedCmd =
  "/usr/bin/git --no-pager -c core.hooksPath=/Users/dfrazer/patchbay-teams-data/teams-safe/476c429a-e307-448b-9012-36c8e68a770d/hooks -c core.fsmonitor=false -c core.sshCommand= -c protocol.ext.allow=never -c commit.gpgSign=false -c core.editor=: -c credential.helper= -c core.askPass= add -- hello-live26.txt PB_COMMIT_MSG";
assert(view.command === expectedCmd, "verbatim host command");
assert(
  view.cwd === "/Users/dfrazer/patchbay-teams-data/proj-home/.trees/live26r93688-20261114-01",
  "cwd line",
);
assert(view.askReason?.includes("runs this repository's git hooks and config"), "hooks disclosure");
assert(
  view.askReason?.includes("an approved escalated command runs unsandboxed via a login shell, so your shell profiles run first"),
  "unsandboxed disclosure",
);

console.log("permissionCard.workerGit.selftest: ok");
