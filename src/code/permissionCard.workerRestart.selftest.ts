import type { AcpPermissionRequest } from "../lib/ipc.ts";
import { permissionCardView } from "./permissionCardView.ts";

function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`permissionCard.workerRestart.selftest: ${msg}`);
}

const request = {
  options: [
    { optionId: "confirm_restart", name: "Restart worker", kind: "allow_once" },
    { optionId: "cancel_restart", name: "Cancel", kind: "reject_once" },
  ],
  toolCall: {
    toolCallId: "confirmation-fixture",
    title: "Confirm worker restart",
    kind: "other",
    rawInput: {},
    _meta: {
      patchbay: {
        workerRestartConfirm: {
          message: "a previous worker ran here; 2 processes were found and 2 killed; 0 remain; 3 processes could not be checked; detached processes may still remain.",
          found: 2,
          killed: 2,
          remaining: 0,
          unknown: 3,
          complete: false,
          wallMs: 8,
          sweepNote: "same-uid process sweep completed",
        },
      },
    },
  },
} as unknown as AcpPermissionRequest;

const view = permissionCardView(request);
assert(view.workerRestartConfirm?.found === 2, "found count is shown");
assert(view.workerRestartConfirm?.killed === 2, "killed count is shown");
assert(view.workerRestartConfirm?.remaining === 0, "remaining count is shown");
assert(view.workerRestartConfirm?.unknown === 3, "unknown process count is shown");
assert(view.workerRestartConfirm?.message.includes("3 processes could not be checked"), "unchecked process count is explicit");
assert(view.workerRestartConfirm?.complete === false, "partial sweep is marked incomplete");
assert(view.workerRestartConfirm?.wallMs === 8, "sweep duration is shown");
assert(view.workerRestartConfirm?.message.includes("detached processes may still remain"), "residual warning is shown");
assert(view.actions.map((a) => a.optionId).join(",") === "confirm_restart,cancel_restart", "restart and cancel actions render in order");
assert(!view.showAlwaysRule, "no persistent rule is offered");

console.log("permissionCard.workerRestart.selftest: ok");
