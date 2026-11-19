# What the model decides, and what the code derives

A record of where the boundary actually sits, written because the question
"what does the plan from the model look like?" has no answer: there is no plan
from the model. This documents what the extractor returns, what `generic.py`
derives from it, and the two places where that derivation is known to be
thin.

## The boundary

The extractor returns **one JSON object with 26 keys** and nothing else:
`cve_id`, `product`, `affected_range`, `version_evidence`, `protocol`,
`ports`, `auth_required`, `build_strategy`, `poc_context`,
`marker_candidate`, `setup_packages`, `setup_units`, `attacker_packages`,
`attacker_pip`, `app_dir`, `fixed_versions`, `poc_entrypoint`, `poc_argv`,
`privesc_shape`, the four `poc_command*` fields, `launch`, `place`,
`dockerfile`, `artifact_candidates`, `citations`.

Those are **observations with citations**. Every *decision* is made by
`generic.derive()` (`src/xentry/generic.py`), which returns a
`TargetInstance` - and that object is the plan.

One property runs through all of it: **each derivation either produces a
value or refuses.** Nothing falls back to a plausible default. `snapshot_for`
returns `""` rather than today's date; `entrypoint` refuses rather than
picking between two scripts; `_reason` refuses with a sentence a reader can
act on.

## 1. Admissibility, before anything else

`_reason(facts)` returns a sentence or `None`. A sentence becomes
`NoObservable` and no job is created. It refuses when:

- `poc_context == "local"` but `privesc_shape` is not one of the relays the
  harness has - the channel is never the problem, the *shape* is: how this
  particular exploit accepts the command that reads the root-only nonce.
- it is a kernel CVE and **not** local: the reboot and the `uname` assertion
  live only on the local path, so "a remote one would report a result about a
  kernel that was never booted".
- a `fixed-command` PoC gives no quoted command, or the quote does not
  contain the span naming the command the harness must replace.
- remote with no extracted port and no standard port for the protocol.
- ports out of range, or more than `MAX_PORTS`.

## 2. The dates

```
advisory_published(cve_text)   NVD 2.0 vulnerabilities[0].cve.published
                               or CVE 5.x cveMetadata.datePublished, else ""
snapshot_for(published)        published - 1 day, floored to 00:00:00Z
cutoff_for(published)          the same instant, as 2022-02-17T00:00:00Z
```

**This is the advisory's publication date, not the release date of the
vulnerable version.** The question asked of the archive is "what were you
carrying the day before anyone knew", and one rule in two formats is what
makes the apt archive and the package registry agree on the same moment.

`""` is not a fallback to "today". It means no date could be derived, and the
broker then starts **no registry proxy at all**, because resolving against a
live registry pins whatever semver answers now - for a recent CVE, usually
the fix.

## 3. The base image

`release.resolve(packages, affected_range, releases, fetch_fn,
fixed_versions)` asks each candidate release's archive which versions it
actually publishes, and takes the newest release publishing a version the
advisory names. `version_prefixes` falls back from `2.4.49` to `2.4`.
`release_for()` turns the result into `base_image_id`, and
`expected_version = resolution.prefix` is what lets readiness assert *the
affected build is listening* rather than *something is listening*.

`upper_bound()` exists because that fallback would otherwise install the fix.
From its own docstring: `"< 1.2.23"` yields prefixes `["1.2.23", "1.2"]`; no
archive carries 1.2.23, so `"1.2"` matched and the newest 1.2.x won - Cacti
1.2.26, five releases past the fix. The job provisioned, passed readiness and
the PoC failed against a patched package, "which looks exactly like a PoC
that does not work".

`fixed_versions` from the advisory is the preferred bound. Failing that the
range's own wording decides direction: `< 1.2.23` excludes it, `3.2.1 and
below` includes it, a bare `2.4.49` includes it.

Every lookup is made and none is cached, deliberately: "the queries are the
record of what was asked".

## 4. local vs remote: the one switch

```python
is_local(facts) = facts.poc_context == "local" and facts.privesc_shape in PRIVESC_STEPS
```

That single boolean selects the attacker profile (`None` vs
`attacker-remote`), the ports (`()` vs `ports_for`), the nonce path and mode,
the null actor's location (`target` vs `attacker`), the evidence channel
(`host_serial` on `org.xentry.evidence.0` vs `attacker_transcript` on
stdout+stderr), and both criteria lists.

## 5. The step ids are script ids

| field | rule |
|---|---|
| `setup_step_id` | `setup-docker` if `facts.dockerfile is not None` else `setup-generic` |
| `readiness_step_id` | `readiness-local` if local else `readiness-generic` |
| `build_step_id` | always `build-poc-generic` |
| `invocation_step_id` | `PRIVESC_STEPS[privesc_shape]` if local, else `run-poc-generic` |
| `null_step_id` | `null-local` if local else `null-generic` |
| `probe_step_id` | `probe-generic-serial` if local else `probe-generic-transcript` |

`PRIVESC_STEPS` is the whole local vocabulary, and it is a table of exploit
*shapes* rather than of products:

```
stdin-shell   -> run-poc-local-stdin     a root shell reading commands on stdin
argv-command  -> run-poc-local-argv      takes the command as an argument
fixed-command -> run-poc-local-patch     embeds it; the relay is substituted in
pty-shell     -> run-poc-local-pty       calls isatty(); piping does nothing
setuid-drop   -> run-poc-local-setuid    finds what appeared rather than being told
two-stage     -> a helper must run first
```

**Two naming problems, recorded rather than fixed.** These fields hold
*script* ids - keys in `steps.yaml` naming a file and its sha256 - while a
job's `job_steps.name` (`provision`, `real_actor`) is the *position*. And
`probe_step_id` names something from a different namespace entirely: probes
are not `exec`'d scripts, they are broker verbs (`read_host_evidence`,
`http_probe`), and no `probe-*` entry exists in `steps.yaml`.

## 6. The success criteria

`what_proves` / `what_does_not_prove` are **constants selected by path** -
`PROVES_LOCAL` vs `PROVES` - with `DATED_CAVEAT` appended when a release
resolved but carried no version prefix. For a derived target they are written
to `criteria.json` at plan time, because a derived target's claims are not a
constant the audit page can look up by target id: they are "recorded as
evidence at the moment they were decided".

## 7. The invocation

`entrypoint(facts)` takes `poc_entrypoint` verbatim, refuses absolute paths
and `..`, and refuses outright when the PoC names no file: "this harness will
not pick one for you", because autodetection "would make the choice silently,
and that choice decides what 'the PoC' even means for the verdict".

`poc_argv` passes through as **tokens**, and the placeholders are substituted
in the step script, not in Python (`run-poc-generic.sh`):

```sh
"{ip}")         argv+=("$target_ip")
"{port}")       argv+=("$port")
"{read_nonce}") argv+=("cat $nonce_path")
```

So the guest-side script resolves them against values the broker gave it. The
model never sees an address or the nonce path.

## 8. The exec params

`provision` receives `suite`, `archive`, `check_valid_until`, `packages`,
`units` (through `generic.tokens(..., "unit")`, which validates every token),
`sources_format`, `ports`, and only when a package was approved:
`artifacts`, `launch`, `place`. Each is derived from the facts plus the
resolved release plus the network's recorded pins, and `validate_params` in
the broker refuses any key the step does not declare.

## 9. Not derived at all: the PoC pin

`derive()` leaves `commit`, `files` and `sha256` empty, and the `stage_poc`
step fills them from the bytes it actually fetched - "nobody knows the digest
of an arbitrary repository in advance". That is a weaker pin than a
checked-in target's: it says *these are the bytes that ran*, not *these are
the bytes the vendor published*. The difference is recorded as evidence
rather than papered over.

## The two version checks, and the gap between them

The resolved package **is** checked against the advisory's range, twice, at
two different times.

At resolve time, in `release.py`:

```python
hits = sorted(item for item in published
              if _matches(item, prefix)
              and (ceiling is None or within(item, *ceiling))
              and not PORT_ONLY.search(item))
```

At readiness time, inside the guest (`readiness-generic.sh`):

```sh
installed="$(dpkg-query -W -f '${Version}' "$package")"
case "${installed#*:}" in "$expected"|"$expected".*|"$expected"-*|"$expected"[a-z]*) ;;
  *) echo "installed $package $installed does not match $expected"; exit 1
```

**The two do not share a bound.** Resolution queries the archive index -
Launchpad per suite, or Debian's snapshot index across the whole archive's
history - while the install comes from the dated serial. Resolution therefore
chooses the image and an expected *prefix*, and readiness verifies only that
prefix. The ceiling is applied at resolve time against the archive's full
version list and never against what the snapshot actually served, so a build
inside the prefix but **above the fix** passes readiness if that serial
carried it.

This is the same class of bug `upper_bound` was written to kill, one layer
further down. Open.

Also open: `segments()` is wired at the wrong stage, so `resolve()` and
`by_package()` still collapse multi-branch ranges. That is why advisories
fixing several branches at once - Ghostcat names 9.0.31, 8.5.51 and 7.0.100 -
are refused rather than resolved.

## The step sequence is control flow, not data

There is no plan document listing `fetch -> extract -> plan -> ...`. The
sequence **is** the control flow of `runner.py`:

```python
_step(..., 1, "fetch", ...)              # hardcoded positions 1-5
_step(..., 2, "extract", ...)
_step(..., 3, "plan", ...)
_step(..., 4, "create_network", ...)
_step(..., 5, "create_target", ...)
if approved:        "stage_approved"
                    "provision",  target.setup_step_id
                    "readiness",  target.readiness_step_id
if not local:       "create_attacker" / "setup_attacker"
...
next_seq = 12 + staged + app_staged + armed
```

Three different things decide which steps exist:

1. **Hardcoded positions** for the first five, then **arithmetic** -
   `next_seq = 12 + staged + app_staged + armed`, which is why `seq` numbers
   differ between jobs.
2. **Conditionals in the function body** - `if approved:`,
   `if target.poc_context == "local":`, `if target.control_port:`,
   `if target.target_id == "gitlab":`.
3. **The `TargetInstance`**, which supplies *which script runs at a
   position* - never whether the position exists.

So `derive()` **parameterises** the pipeline; it does not describe it. The
audit page's Steps card is a record of which branches executed.

The step names a job can record: `fetch`, `extract`, `plan`,
`create_network`, `create_target`, `stage_approved`, `provision`,
`readiness`, `create_attacker`, `setup_attacker`, `lock_network`,
`stage_poc`, `copy_poc`, `build_poc`, `freeze`, `null_actor`, `probe_null`,
`restore`, `real_actor`, `target_probe`, plus `author_poc` (the pocgen path)
and `control_actor` (the fixed-version control). The last two have never run
on this host.

## Steps, verbs and privileged actions

Three words for three things, which the audit page shows in two cards:

| | what it is | where it lives |
|---|---|---|
| **step** | one position in the job's plan: `seq`, name, script id, state, reason | `job_steps` -> the **Steps** card |
| **verb** | one *kind* of privileged operation; a fixed vocabulary of 27, each with a declared parameter set | `VERB_PARAMS` in `broker/main.py` |
| **privileged action** | one *call* of a verb: verb, params sha256, status, timing | `broker_calls` -> the **Privileged actions** card |

They are not one to one in either direction. One step usually becomes several
privileged actions - `provision` is an `exec` plus the `copy_in` and
`stage_artifact` calls that fed it. Some verbs belong to no step
(`create_network`, `lock_network`). And `fetch`, `extract` and `plan` make no
broker call at all, being pure host-side work.

## How the model reaches the broker: it does not

```
client.call(...) in src/xentry/runner.py          38 sites
client.call(...) in extract / validator / pocgen   0 sites
```

The path is **model -> runner -> broker -> libvirt and guests**, with the
model two boundaries away from anything privileged. Three gates sit between a
model's output and a command running:

1. `VERB_PARAMS` rejects an unknown verb *and* an unknown parameter before
   anything executes.
2. `exec` cannot run a command. It takes a `step_id`, resolves it against the
   registry, refuses a script whose bytes do not match the recorded sha256,
   refuses parameters the step does not declare, and refuses a user not in
   `allowed_users`. The worst a bad plan can do is name a step that already
   exists on disk at a known digest.
3. The socket. `/run/xentry` is `drwxr-x--- root:xentry` and the broker checks
   `SO_PEERCRED`.

## Can the npm path be generalised?

Yes. The shape is not about Node: *the vulnerable package is a dependency of
some host application, the lab reproduces through that application, and a
control run reinstalls the closure at the fixed version to show the finding
moves with it.* That applies to pip, composer, cargo, go and maven without a
change of idea.

| npm-specific | already ecosystem-agnostic |
|---|---|
| `read_app()` parses package.json | `subject_for()` - which package the control moves |
| `declared_version()` walks that map | `fixed_for()` - the version to move it to |
| `manifest_url()` builds a raw package.json URL | `control_port_for()` - the control's port |
| `_command()` maps a start script to its port | `closure_id()`, and all of `derive()` |

The serving side is general already: `RegistryProxy` carries pypi, npm and
nodejs with their own filters and one cutoff rule. So generalising means an
**Environment reader per ecosystem** - a small interface returning
`{dependencies, start command, port}` - and leaving the selection logic
alone.

Not done yet, and the reason is recorded in `ecosystem.py` above `read_app`:
exactly one CVE has needed it (CVE-2026-126187, react reproduced through
next), and the subject-is-not-the-product rule was only discoverable
*because* a real advisory named react while the tree carried next. A pip case
would tell us whether extras and environment markers belong in the interface;
guessing that now is how a closure id ends up meaning different things in
different ecosystems.
