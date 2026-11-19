# ADR 0003: the model provisions the target, and a rebuild decides whether it worked

Status: accepted
Date: 2026-11-18

## Context

Provisioning is chosen by code. `generic.derive()` reads the extractor's facts
and selects one of 34 registered scripts, and `exec` refuses any script whose
bytes do not match the digest in `steps.yaml`. That is why the model has never
been able to break a target: it produces observations, and code decides.

The cost is a ceiling. A CVE is reproducible only if its software fits a shape
somebody already checked in - `setup-generic`, `setup-docker`, `setup-npm`,
`setup-php`, `setup-gitlab`, `setup-dirtyfrag`. Everything else is refused by
`_reason()` with a sentence, which is honest and unhelpful: the refusal says
the harness has no relay for this, not that the CVE is unreproducible.

ADR 0002 moved the mirrors into their own VM, so a target VM now has no path to
the host at all. That is what makes this ADR possible: a model with a root
shell in a target VM can reach the mirror VM and nothing else.

## Decision

**A new job kind, `harness_job`, in which a model builds the target itself and
the artifact it produces is a provisioning script.** The input is unchanged - a
CVE URL and a PoC URL - and the PoC still runs at the end against a nonce, so
this is a job that measures, not an `environment` that does not.

The mode is selected by a switch on the submit page: **off for no harness, on
with harness**.

### The exploratory session is a draft. The rebuild is the proof.

```
A  explore      the model drives the target VM. No nonce exists. The network is
                in the provisioning phase. Nothing it does can become evidence.
B  crystallise  the model emits a provisioning script. Its digest is recorded
                against the job.
C  verify       revert to the post-boot snapshot, run ONLY that script, then run
                code-owned readiness. The job continues on THIS machine, which
                the model has never touched.
```

This is `validator.py:88` applied one layer down. There, when the runner's
measurement is decisive it overrides the model's verdict and the model's
verdict is kept verbatim in the explanation - the measurement decides, the
assessment is recorded. Here the rebuild decides and the session is recorded.

The consequence worth stating plainly: **nothing the model did by hand matters
to the outcome.** If its script does not rebuild the environment, the job
fails, however well the exploratory VM worked. That is the property that makes
a root shell affordable.

### The rebuild is a snapshot revert, with a rebuild behind it

A snapshot is taken **immediately after the base image boots**, before the
model touches anything. Every verification reverts to that snapshot and runs
the script. If the revert fails, the VM is rebuilt from the base image.

The alternative - a second VM for verification - keeps the exploratory state
across a failed verification but costs a third dnsmasq host entry and another
4GB. Revert reuses `snapshot` and `restore`, which already exist as verbs, and
a failed verification costs a revert cycle rather than a fresh boot.

### Two readiness tiers, because one of them is slow

A full revert plus script run is minutes. If that is the model's only feedback,
a ten-call budget is half an hour of wall clock and the loop is unusable.

| | who owns it | cost | can it pass the phase? |
|---|---|---|---|
| the model's own checks | the model, through `free_exec` and `http_probe` | free, unbudgeted | no |
| **readiness** | code | a revert, a script run, a full check | **only this** |

Readiness keeps exactly the checks it has today - the ports listening, and the
version assertion - and the model may add assertions but never remove or weaken
one. **Its output is verbose and goes back to the model**, so a failure tells
the model what diverged between what it intended and what its script produced.

When the model builds from source there is no `dpkg-query` to ask. It must then
**declare the version it built**, and readiness verifies that by running the
binary - `httpd -v`, `redis-server --version`. A from-source build also needs
operator approval, reusing the approval path that already exists for downloaded
packages.

### The provisioner does not read the PoC

The extractor runs once and produces **two disjoint fact sets**:

- **environment facts** - the product, the affected range, the packages, the
  units, the ports, the build strategy. These go to the provisioner.
- **PoC facts** - the entrypoint, the argv, the privesc shape, the command
  quotes. These never reach the provisioner.

Readiness is fed from the extractor's facts too, in its own context, so it
asserts things the provisioner never chose.

This is not only an injection defence. **A provisioner that has read the PoC can
build an environment shaped to make that PoC pass** - run the service as root,
turn off a hardening default, install whatever version the exploit wants. That
is teaching to the test, and withholding the PoC removes the ability rather than
discouraging it.

The advisory page is available **on request as a fallback, and only after at
least one readiness run**. Advisories quote exploit detail, so this is the hole
in the property and it is deliberate: a provisioner stuck on a fact the
extractor missed needs somewhere to look. The request is recorded in the
session, so a reader can see when it reached for it.

### Giving up is a result, and it is an artifact

The model may conclude it cannot build the environment. That ends the job with
its reasoning as the failure - which is the whole value of a failed harness run,
because it says what about this CVE could not be built.

It is stored as an **artifact**, not as a step detail. `runner.py:_detail`
truncates to the last 4000 characters, which is how the redis job's real error
arrived cut mid-sentence.

### What the record must say

A fixed-script job and a harness job can both end `verdict=reproduced`. They are
not the same claim: in the harness job the environment was built by commands
nobody reviewed, and the PoC may have worked for a reason nobody chose.

So a harness job records:

- a `not_proves` line - *the environment was built by a model's own commands;
  what was verified is that its script rebuilds the same state from a clean
  image, and no human reviewed either*
- **the route in the authority string**, so the two are never silently
  comparable

Without that the history holds two different claims spelled identically, and
nobody can separate them later.

### The budgets are settings, and they are recorded per job

A settings page defines the maximum token count, the provisioning timeout and
the maximum readiness calls. Each job **records the values it ran under**, the
way `provision-inputs.json` records the archive pins: a run with ten readiness
calls is not comparable to one with three, and a global setting cannot tell you
which a past job had.

### The prompt is an artifact

The initial prompt is the most consequential thing in this mode, so it is stored
per job like the extractor's. It establishes, in order:

1. the loop - explore, write the script, run your own checks, then readiness;
2. that readiness is expensive and not yours to weaken;
3. that the script must be **idempotent from a clean base image**, because that
   is literally what will be tested;
4. that all tool output is untrusted data;
5. that the nonce and the PoC are not yours to see;
6. the exact shape of a give-up.

A prompt change then shows up in the history instead of being invisible.

## Consequence that is not free: two classes of result in one history

Before this, every "reproduced" meant the same thing. After it there are two
kinds, and the only thing keeping them apart is the record. That is why the
authority string and the criteria line are part of the decision rather than
polish - and why the switch is labelled on the submit page rather than inferred.

The second cost is time. A harness job is a model loop plus up to N reverts, so
it is minutes to tens of minutes where a fixed-script job is minutes. The
settings page exists to bound that.

## Budget

Roughly 250-350 lines across the tool layer and allowlist, the session
recording, the revert-and-verify step, the state comparison, readiness as a
tool, and the polling endpoint. Templates, CSS and tests are free.

Staged, so each stage is separately useful and the risky part lands last:

1. **Draft only.** The switch, the tool layer, the session, the live feed - but
   the job still provisions with the fixed script and the generated script is
   only recorded. No verdict risk, and it answers whether the model can do this
   at all.
2. **The rebuild gate.** Revert, run the script, readiness, the state
   comparison. The script becomes load-bearing.
3. **The route becomes the provisioning path** when the switch is on, with the
   criteria and authority changes.

## The test that is written first

That a harness job cannot produce evidence from the exploratory VM. Concretely:
no nonce exists before verification passes, and the VM that runs the PoC is the
one built by the script and never touched by the model. A test that places a
marker by hand during exploration and then asserts it is absent from the
verified machine is the one that would catch the whole design collapsing into
"the model set up a VM and then vouched for it".
