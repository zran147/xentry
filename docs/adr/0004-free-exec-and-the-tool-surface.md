# ADR 0004: free_exec, and what the broker will let a model drive

Status: accepted
Date: 2026-11-18

## Context

Three gates stand between a model's output and a command running as root:

1. `VERB_PARAMS` rejects an unknown verb **and** an unknown parameter before
   anything executes.
2. `exec` cannot run a command. It takes a `step_id`, resolves it against the
   registry, refuses a script whose bytes do not match the recorded sha256,
   refuses parameters the step does not declare, and refuses a user not in
   `allowed_users`.
3. The socket. `/run/xentry` is `drwxr-x--- root:xentry` and the broker checks
   `SO_PEERCRED`.

Gate 2 is the one ADR 0003 has to open, because a model that may only run
pre-registered scripts cannot build an environment nobody has scripted.

## Decision

### `exec` does not change. A new verb, `free_exec`, is added

`free_exec` takes a command and runs it in a VM. `exec` keeps its name, its
digest check and its parameter validation, and every existing call site is
untouched.

The alternative considered was renaming `exec` to `restricted_exec` and giving
the new verb the short name. **Rejected because it rewrites the meaning of
history**: every `broker_calls` row ever recorded says `verb='exec'` meaning the
restricted one, and after such a rename a reader of any past job's Privileged
actions card would see `exec` and read it as the permissive verb. Keeping `exec`
as it is means no migration, and no row ever changes meaning.

The audit consequence that remains: `free_exec` rows must be **visually
distinct** in the Privileged actions card. A card where the two verbs look alike
is a card that hides the only thing worth noticing.

### The model does not reach the broker

The broker trusts one unprivileged caller, identified by `SO_PEERCRED`. A model
has no identity it could present and never will. So the agent loop runs **inside
the runner process**, and the runner translates a tool call into a broker call
after checking it.

"The model calls verbs" is therefore shorthand. The real shape is: the runner
offers a mediated subset of tools, and **the tool layer is the new trust
boundary**. It is ours, it is in our process, and it is where the allowlist
lives.

### The allowlist is scoped by phase and by VM

`RUNTIME_VERBS` is global and phaseless today. The tool layer adds two
restrictions, both of which must hold:

- **the subject is the job's target VM** - resolved from `vm_id`, never taken
  from the model
- **the phase is exploration** - outside it the tool layer offers nothing

| the model gets | withheld | why |
|---|---|---|
| `free_exec`, `copy_in`, `copy_out`, `http_probe`, `snapshot`, `restore`, `reboot` | **`place_nonce`** | a model that can place or read the nonce makes every verdict worthless |
| readiness, as a tool | `lock_network`, `create_*`, `destroy_*` | phase and lifecycle stay code-owned |
| | `read_host_evidence` | that is the evidence channel for local jobs |
| | `stage_artifact`, `proxy_capture` | not needed to build a machine |

`snapshot` and `restore` are given deliberately: they are the model's cheap
undo, and they already exist.

### `exec` gains a second digest comparison, for a per-job script

A generated script cannot live in `steps.yaml` - it belongs to one job. So the
gate learns a second mode: compare against **the digest recorded for this job's
generated script** rather than the manifest's.

This is what lets a passed job be re-provisioned later from a script a reader
can review, and it is what the verification phase runs: readiness invokes the
generated script through `exec`, not through `free_exec`, so the thing that
builds the final machine is digest-checked like everything else.

## Consequence that is not free

`free_exec` is a logged root shell in a VM. Nothing dresses that up. What makes
it affordable is everything around it rather than the verb itself:

- the target VM has no path to the host (ADR 0002) and no path to the internet;
  it reaches the mirror VM and nothing else
- no nonce exists during exploration
- the VM is reverted before anything is measured, so its hand-made state cannot
  reach a verdict
- every command and its output are recorded

The risk that is genuinely new is **prompt injection with consequences**. Today
the model reads untrusted advisory and PoC text and emits data. With `free_exec`
it reads untrusted text - and tool output, which is also untrusted - and emits
commands. A PoC repository can contain text aimed at the model. The blast radius
is a disposable VM on an island network, which is the containment; the loop's
*direction* can still be steered, which is why the rebuild gate carries all the
weight and why the budgets are hard.

## Budget

Small on its own: the verb, its parameter set, the handler, and the allowlist.
The tool layer itself is counted in ADR 0003.

## The test that is written first

Three properties of the gate, because `_sha256_file(local_script) !=
spec.sha256` is the single line that makes any of this containable:

1. **A manifest step cannot be run through the job-digest path, and a job
   script cannot be run through the manifest path.** Otherwise the new branch
   becomes a way to execute `setup-generic.sh` with an unchecked digest.
2. **The digest recorded is the digest executed.** The script is regenerated
   repeatedly by design, so a stale digest must refuse rather than run the new
   bytes.
3. **A job's script runs only for that job.** `exec` already resolves `vm_id` to
   a `job_id`; job A's script must not execute against job B's VM.

And one for the verb surface: **`place_nonce` is not reachable from the tool
layer in any phase.** Not "is not offered" - not reachable, asserted against the
allowlist rather than against the tool list.
