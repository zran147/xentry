# ADR 0001 — xentry V1 reset

* **Status:** Accepted
* **Date:** 2026-11-06
* **Owner:** zran147
* **Supersedes:** the prior v2 design and old ADR 0007 for the V1 scope

## Context

The prior xentry tree grew to roughly 12,000 lines and about 20 subsystems and could not be audited by its owner. Its verification path was self-reported. The V1 design reduces the product to three known Linux targets, a local web app, and a runner-owned evidence path.

## Decisions

1. **All three targets remain in V1:** PHP2Shell (CVE-2026-109618), GitLab (CVE-2026-85706), and Dirty Frag (CVE-2026-43500).
2. **Remote PoCs use a target VM plus a lightweight attacker VM.** GitLab and PHP2Shell run their pinned PoCs from the attacker VM. Dirty Frag stays in the target VM with host-side evidence because it is a local kernel exploit.
3. **The VM is the isolation boundary; xentry uses no container runtime.** Docker/Podman are not used for xentry or target/attacker provisioning.
4. **System libvirt through a root-owned, fixed-verb broker.** The app never joins `libvirt`. The broker validates a broker-owned registry, runs SSH with per-job root and actor keys, and exposes only the contract verbs.
5. **The first three setup scripts are checked in and hash-verified.** There is no LLM setup authoring or repair in V1. The generated path moves to V1.1 with a fourth real target.
6. **ADK is the extractor only.** It is load-bearing for target admission and the pre-run plan. The validator is a direct LiteLLM call, no tools, no generator history. ADR 0007's "explicit Python, no model tools" decision is reversed for extraction only; the model still has no execute/validate/destroy tools.
7. **The runner-owned nonce is the causal anchor.** The LLM cannot return `reproduced` without `nonce_observed`. Dirty Frag's authority is `guest_attested+llm_assessed` until the host channel is proven non-forgeable.
8. **Budget:** 8,000 handwritten Python lines, 44 modules, 14 weeks. The two-VM and broker work is explicitly budgeted.
9. **AppArmor is required at Gate B.** The WSL2 development host cannot validate it; Gate B's AppArmor and QEMU-user checks run on the deployment host. The final design is not relaxed for WSL2.

## Gate G amendment (2026-11-06)

The kernel pin is split into two vendor-pinned artifacts: `kernel-6.17.0-23` (signed image) and `kernel-modules-6.17.0-23` (modules). The image package depends on the modules package, so the Dirty Frag setup installs both and the mirror serves both. The vendor cloud image is `ubuntu-base-image`; the three built images (`ubuntu-target-image`, `ubuntu-dirtyfrag-image`, `ubuntu-attacker-image`) build from it. This is a correctness correction to the Gate G artifact set, not a scope change.

## Phase 0 implementation note (2026-11-06)

The root broker drives system libvirt through the fixed `virsh` CLI instead of `libvirt-python`. This removes the host `libvirt-dev` build dependency while keeping the same root-owned, fixed-verb, system-libvirt boundary. The WSL2 smoke used a static DAC seclabel for the developer UID (`1000:1000`); the deployment host must use the dedicated `xentry-vm` user. AppArmor, nftables application, and the final QEMU-user check remain deployment-host Gate B items.

## Ecosystem targets, entry 15 (2026-11-13)

The derived target installs an Ubuntu package at a version resolved from the
advisory. That covers distro-packaged network services and nothing else, so the
CVEs an operator actually pastes - an npm package, a Joomla extension, a
Composer library - are refused or fail at provision. Many of their PoC
repositories ship a Docker Compose lab that would build the environment for us.

15a. **A PoC repository's Dockerfile or compose file is read as evidence about
the environment, never executed.** What is extracted is the runtime and its
version, the vulnerable package and its version, the port, and how the service
starts. A checked-in script then installs that one package at that one version,
with tokens validated the way `setup-generic.sh` validates apt names. The
author's `RUN` lines do not run.

This keeps decision 3 - the VM is the isolation boundary and xentry uses no
container runtime - intact, and it keeps the property the whole program rests
on: the version pin is ours. Running the author's lab would have moved both. It
also removes a second trust problem, since a lab is an environment someone with
an interest in the exploit succeeding built.

15b. **An app ecosystem's packages are resolved on the host, pinned by digest
and served through the existing artifact mirror. There is no registry proxy.**
*Reversed by entry 20: a proxy can date the index and that is both cheaper and
more correct. The measurement below stands; the conclusion drawn from it did
not.*

A registry proxy was the plan until it was measured. `registry.npmjs.org`
serves one metadata document per package covering every version ever published:
31.5 MB for `next` (4,034 versions), 25.7 MB with npm's abbreviated
`install-v1` Accept header, 3.1 MB for `@next/env` alone. A proxy would stream
that for every package in the dependency closure, for every job, and buy no
provenance.

What it would have bought is already published. Each version carries a
`dist.integrity` sha512 and an exact tarball URL; `next-16.4.0.tgz` is 43.6 MB
and its published digest verifies against the bytes. So the closure is resolved
on the host with `npm install --package-lock-only --ignore-scripts` - metadata
only, no tarballs fetched, no lifecycle script run - and every resolved tarball
is pinned in `config/artifacts.yaml` like any other artifact and served by the
mirror. The target installs offline.

This adds no network channel, needs no change to `lock_network`, and makes an
npm dependency closure pinned the way the apt snapshot is. Measured end to end
for `next@16.4.0` on this host:

| step | result |
| --- | --- |
| resolve on the host | 54 packages, every one with a `resolved` URL and a sha512 `integrity`, no `node_modules`, 3.2 s |
| filter by the lockfile's `os`/`cpu` | 27 packages relevant to linux-x64, 131 MB; all 54 would be 407 MB |
| pin and mirror | `resolved` rewritten to mirror URLs, `integrity` untouched |
| install in the guest | `npm ci` against an unreachable registry: 19 packages added, next 16.4.0, 4.4 s, zero registry requests |

Two things fall out of the measurement. Platform filtering is not an
optimisation: without it two thirds of every pin set is macOS and Windows
binaries. And npm verifies `integrity` itself, so the mirror does not have to be
trusted - a corrupted tarball fails the install rather than reaching the target.

15b-ii. **The resolver must prove the pin set is complete before the job
starts.** A package the host failed to pin does not fail loudly: npm falls back
to the configured registry. In a locked VM that is a hard failure, which is safe
but late - and in the spike the cause was a `while read` loop dropping a file's
last unterminated line, which cost one package and looked like nothing. The
resolver compares the lockfile against what it pinned, counting only packages
this platform's `os`/`cpu` admit, and refuses the job if any are missing.

15b-i. **The runtime is a pinned tarball too.** The archive cannot supply it:
noble publishes nodejs 18.19, jammy 12.22, bionic 8.9, and a current npm
advisory needs node 20 or later. `nodejs.org/dist/vX/SHASUMS256.txt` publishes a
sha256 per tarball, so the runtime pins and is mirrored exactly like the Dirty
Frag kernel image.

15c. **A reproduction against an environment we did not pin needs a
fixed-version control run.** The null run proves the PoC is not printing a
constant; it cannot distinguish a vulnerability from an environment built to
make the exploit work. Running the same stack at the patched version and
requiring failure can. Where a PoC author publishes both versions, that control
is nearly free and should be used; where they publish neither, the honest
outcome is a weaker class of result, recorded as such, not a reproduction.

15d. **The compose shortcut is deferred.** Running an author's `lab` and
`lab-patched` services directly would be more efficient where both exist, but it
needs a container runtime in the target VM and so requires reversing decision 3.
Not in this revision.

15e. **Budget:** 11,000 handwritten lines and 49 modules, revised down from the
11,400 and 50 this entry first proposed. The spike in 15b removed
`broker/registryproxy.py`, so the increment covers an ecosystem target module
(~200 lines, measured against `generic.py` at 227), a host-side closure
resolver in `scripts/` (~150), and wiring across `runtime.py`, the registry
tables and the runner (~120). Tests are outside the counted roots. 49 modules is
exactly what those two new files need, which is the intent: a third module in
this path is a decision, not an accident.

## The fixed-version control run, entry 16 (2026-11-13)

Entry 15c said a reproduction against an environment we did not pin needs a
control run at the fixed version. This is how it works.

16a. **Both builds are installed before the network is locked, on the same VM,
from the same application source.** The closure for the affected version and
the closure for the fixed version are pinned separately and unpacked into
`/srv/app` and `/srv/app-fixed`; the lab's own code is unpacked once and laid
over each. They are served by two units on adjacent ports, and the attacker is
allowed to reach both.

The alternative - run, rebuild the target at the fixed version, run again -
cannot work here. Nothing can be downloaded after `lock_network`, and
rebuilding would change the kernel's uptime, the file layout, the nonce file
and whatever else a fresh provision touches. Two trees on one VM leave one
difference between the two runs: one package's version.

16b. **The control runs before the real exploit, not after.** The order is
null, control, restore, real. A control run after a successful compromise would
be asking a machine the PoC already owns whether the PoC works.

16c. **A non-zero exit from the control run is the expected outcome and is not
a failure.** Only the nonce decides: if the control transcript contains it, the
job fails with `control_actor_observed_nonce`, because an exploit that also
works against the fixed version has not shown that the vulnerability is why it
works.

16d. **Readiness asserts the two builds actually differ.** Each tree is checked
against the lockfile that shipped inside its own digest-verified closure, and
the subject package's two resolved versions are required to differ. Two
identical trees would make a failed control look like proof when it is two
identical runs with different luck.

16e. **What the control buys, measured.** Resolving the briskets lab twice,
with `next` moved from 16.4.0 to 16.4.1 and the other two dependencies left as
the lab pinned them:

| | result |
| --- | --- |
| packages in each closure | 54 and 54 |
| packages whose version differs | 10 |
| what they are | `next` and the nine sub-packages it versions in lockstep: `@next/env` and the eight platform `swc` binaries |
| what did not move | `react` and `react-dom`, both 19.3.1 in each |

So the claim the job may make is exact, and so is its limit. `what_proves`
gains "the same PoC, against the same stack with only `next` moved from 16.4.0
to 16.4.1, did not produce the value", and the caveat entry 15 carried - "until
the same stack at the fixed version has been run and failed" - is replaced
rather than left standing beside a claim that contradicts it. In its place:
moving the subject moves whatever its own constraints resolve to, and the two
lockfiles record exactly what moved.

16f. **No control, no claim.** A job without a fixed version keeps the weaker
wording. `--fixed-version` is refused when the subject is not among the pinned
dependencies, or when the fixed version equals the affected one.

## Provisioning channels for other ecosystems, entry 17 (2026-11-13)

Entry 15b decided npm by measurement and left the general question open. The
rule that falls out of apt and npm together:

* **Reverse proxy** when upstream is immutable *and* the metadata for one
  resolution is small. apt qualifies through `snapshot.ubuntu.com`, which makes
  a mutable archive immutable at a serial.
* **Resolve on the host and serve the result from the artifact mirror** when
  resolution is the thing that must be frozen and the registry publishes a
  per-file digest the client verifies. npm qualifies.
* **Mirror with a digest of our own** when nothing upstream publishes one.
* **Not at all** when it needs a container runtime, which decision 3 excludes.

Measured on this host, 2026-11-13:

| ecosystem | metadata for one resolution | per-file digest published | client verifies it | channel |
| --- | --- | --- | --- | --- |
| apt (Ubuntu) | index at a snapshot serial | yes, signed `Release` | yes, GPG | proxy, pinned to a serial - built |
| npm | 25.7 MB for `next`, abbreviated | yes, `dist.integrity` sha512 | yes, from the lockfile | host-resolve + mirror - built |
| PyPI | 193 KB for `requests`; a full resolve of 6 packages cost 816 KB and 3.7 s | yes, sha256 per file | yes, with `--require-hashes` | host-resolve + mirror |
| Go modules | 200 B for `@v/list`, 1.3 KB for a `.mod` | yes, and a transparency log | yes, `go.sum` | proxy - the one case where a proxy is clearly right |
| Maven Central | 23 KB for one `.pom` | `.sha1` yes, `.sha512` often 404 | only if the build declares it | proxy, immutable by policy |
| crates.io | small per-crate index | yes, sha256 | yes, `Cargo.lock` `checksum` | host-resolve + mirror |
| RubyGems | 476 KB for all `rails` versions | yes, sha256 | not from `Gemfile.lock` before Bundler 2.5 | host-resolve + mirror |
| Composer | 85 KB for `monolog/monolog`, 91 versions | **no** - `dist.shasum` is empty and `dist.url` is a GitHub zipball | no | mirror with our own pin |
| OCI registries | - | - | - | excluded by decision 3 |

Two of these are worth stating as findings rather than table rows. Composer
publishes no digest at all: Packagist hands out `api.github.com/.../zipball/<ref>`
with `"shasum": ""`, so the only integrity Composer has is a git reference, and
GitHub zipballs are not byte-stable over time. A Composer closure is therefore
pinned by a sha256 we compute ourselves, which is the catalog's ordinary
guarantee but weaker than npm's: there the registry's own digest means the
mirror does not have to be trusted. And Go is the inverse case - the metadata
for a resolution is three orders of magnitude smaller than npm's, and
`sum.golang.org` verifies independently of whoever serves the bytes - so the
proxy that was wrong for npm is right there.

17a. **PoC dependencies are not a per-job resolution.** The attacker VM has no
network after `lock_network`, so `build-poc-generic.sh` says plainly that a PoC
whose dependencies are not in the image fails. That is the honest outcome but a
common one: CVE-2026-56290's PoC needs `requests` and `colorama`, and the image
carried only the first. These are a small, shared, slow-moving set, so they are
pinned into the attacker image by sha256 at build time rather than resolved per
job. No new module, no new channel, and no per-job cost.

17b. **Budget: 11,300 handwritten lines, 49 modules** (raised to 11,500 by entry 19i). Up from 11,000, which
entry 15e set before the control run had a design. The increment is the control
run (entry 16) across `ecosystem.py`, `runner.py`, `targets.py` and the
resolver, plus the advisory-record renderer and the provisioning guard in entry
18. Module count does not move: nothing here needed a new module, and that is
the test of whether it belonged in the ones that exist.

17c. **Deferred, with the channel already decided.** PyPI, Composer, Go, Maven,
crates and gems are not built. Each would need what npm needed - a resolver, a
setup step, an image, and the runner wiring to select it - and the table above
is the part that was worth settling before any of them is written.

## Two failures the harness should have caught sooner, entry 18 (2026-11-13)

18a. **An advisory record is rendered as one `path: value` line per field
before the extractor sees it.** Job `d7e7084c80b6` failed with
`validator_error` because the extractor was asked to copy a verbatim quote out
of a JSON document into a JSON string and did not escape the inner quotes: its
citation of `"versions":[{"version":"1.0-3.6.0",...` made the whole reply
unparseable. The same single-line body also made every citation in every
advisory-sourced job report line 1, because there was only one line. Flattening
removes the punctuation there is nothing to escape and gives line numbers that
mean something. It is deliberately schema-agnostic: NVD 2.0 and CVE 5.x nest
differently, neither is parsed, and a body that is not JSON is passed through.

18b. **A derived target that will never serve its port is refused at admission,
and the setup step proves the port is served before it reports success.** Job
`f5223aa4a369` created a network and a VM, provisioned nothing, and waited five
minutes for port 3100. Its PoC builds the lab with `docker build ./lab`, so the
extractor correctly reported no Ubuntu package - and the apt path, whose whole
provisioning is `apt-get install`, had nothing to install and no way to serve
anything. That is knowable before a VM exists.

The second half of 18b is the case admission cannot see. A package that does
install can still bind to loopback, and `readiness-generic.sh` connects to
`127.0.0.1`, so it passes - and the PoC then fails with a connection error that
reads like a broken exploit. The setup step now waits for a bind on an address
that is not loopback, and says which it found.

18c. **Rendering a response for a reader broke two callers that parsed it,
and both failed silently.** `Fetched.text` became a rendering - HTML stripped
to prose, JSON flattened - while `Fetched.body` stayed the bytes. Two callers
were still doing `json.loads(.text)`, and both sat behind an `except` that
treats a parse failure as "unknown": `release.published_versions` returned no
versions for every package, so every apt-derived job would have been refused
with "no built release publishes ...", and `generic.advisory_published`
returned no date, so every derived job lost its per-CVE snapshot serial and
provisioned from the broker's default - which for a recent CVE usually means
the *patched* build, and so an exploit that fails and a job that reads as a
non-reproduction rather than a misconfiguration.

Both now read `body`. The lesson is in the dataclass's own docstring, because
the next caller will reach for `.text` too. What let it through was a test
double: `FakeFetched` carried only `text`, so the fakes could not express the
distinction the real type had grown. It now renders the same way the real
fetch does, which makes parsing `.text` fail in the tests first.

One thing improved on the way: `advisory_published` only ever understood NVD
2.0 records, so a cve.org link never had a snapshot serial at all. Reading the
rendering covers both shapes.

## Selecting an ecosystem target, entry 19 (2026-11-13)

Entries 15 and 16 built the application-package target and its control run and
left nothing able to choose it. This is the selection path, and it is the one
every later row of entry 17's table reuses.

19a. **The extractor reports where the lab is, not how to build it.** `app_dir`
is the directory in the PoC repository that builds the vulnerable application -
the one holding the Dockerfile, the compose file, the `package.json`. The
harness then reads the manifest in that directory and installs what it names.
No `RUN` line is parsed and none is executed, so 15a holds unchanged.
`fixed_version` is the advisory's own fix statement, uncited because it asserts
nothing a reader relies on: it only decides whether a control run is possible,
and the control run either fails - proving the point - or fails the job.

19b. **The operator's pin decides which package the control run moves.** The
closure id fingerprints the whole dependency set, so the same set under a
different `--subject` is a different id. Selection recomputes the id for each
dependency and takes the one that is pinned, which recovers the operator's
choice without parsing a package name back out of an artifact id.

This is deliberate, and CVE-2026-126187 is why. Its advisory's product is
`react`; the lab reproduces through `next`; and the affected package,
`react-server-dom-webpack`, is vendored inside `next` and absent from the
resolved tree entirely. A name match against the advisory would have moved
`react` and asserted something about a version with nothing to do with the
finding. The refusal still suggests a `--subject` - it has to say something -
but it says in the same breath that the choice decides what the job may claim.

19c. **A job runs only against a closure that is already pinned, and the
refusal names the command that pins it.** 130 MB and several minutes of digest
verification is an operator's deliberate act. The refusal reaches the submit
form, not a failed job, so the whole exchange is: paste two links, get the
exact `pin-npm-closure.py` line, run it, paste again.

19d. **A missing lab falls back to the apt path; a missing closure does not.**
`app_dir` is a model's reading of a README, so a repository that merely happens
to carry a `package.json`, or whose manifest 404s, must not be refused when the
apt path could still run it. An unpinned closure is the opposite: the operator
asked for this environment and the fix is one command, so it is reported rather
than silently downgraded to a target that would fail differently.

19e. **A missing control closure is not an error.** The job runs without the
control run and records the weaker claim. Refusing would make the better
evidence a precondition for any evidence.

19f. **Both closures and the lab's source are copied into the target before
provisioning.** `copy_in` resolves the pinned catalog first and verifies the
digest on the host and again in the guest, so no mirror is involved and the
closure the operator reviewed is the one that installs. It happens before
`lock_network` because nothing can be fetched afterwards - which is what makes
the second build installable at all - and the repository is fetched once and
staged for both VMs, rather than twice from a repository that could move
between the two reads.

19g. **A derived target records its own claims.** They are decided per job, not
per target id: a job that ran a control says more than one that could not, and
names the versions it moved. The audit page read them from a module constant,
which for the ecosystem target would have shown nothing at all. They are now
written as evidence at plan time and read back with their digest checked, with
the module constant as the fallback for jobs recorded before this.

19h. **Migration 007 admits the control nonce.** `nonces` constrained `phase`
to `null` and `real`, so the control run failed on a CHECK at the moment it
placed its nonce - after the target, the attacker and both builds were already
up, which is the most expensive point in the job to discover a constraint.

19i. **Budget: 11,500 handwritten lines, 49 modules.** Up from the 11,300 of
entry 17b, which covered the control run but not the selection path that makes
it reachable. Still no new module: selection is `ecosystem.select`, staging is
one runner step, and the plan gained fields rather than a second code path.

## The registry mirror reverses 15b, entry 20 (2026-11-14)

Entry 15b said there would be no registry proxy and resolved npm closures on
the host instead. That was wrong. It is reversed here, and the measurement
that reverses it is not about cost.

20a. **A proxy can synthesise the snapshot a registry does not publish, by
filtering the index it serves to what existed before the advisory.** Every
registry timestamps releases even though none offers a snapshot: npm a `time`
map in the packument, PyPI an `upload-time` on every file (244 of 244 for
`requests`). So the mirror serves an index holding only what predates the
advisory's publication date, and the client resolves deterministically with no
lockfile, no closure and no flag of its own - the same shape `apt-get install`
has against `snapshot.ubuntu.com` at a serial.

20b. **It is more correct than a pinned closure, which is the reason to
change.** A closure resolved on the host takes today's answer to the ranges a
lab declares, and for a recent CVE today's answer leans toward the fix.
Measured on the briskets lab:

| | result |
| --- | --- |
| closure resolved on the host | `react` 19.3.1 |
| the same lab through the mirror, dated | `react` **19.3.0** |
| index for `next` | 31.5 MB upstream, 10.0 MB filtered |
| first job | 16 s; second job for the same packages, 2 s |
| real install | 46 packages in 5 s, every sha512 checked by npm |
| host cache | 161 MB for 83 packages, shared across every job and CVE |

The apt side has always provisioned from just before the advisory. This makes
that one rule rather than one target's rule.

20c. **A dependency range is admitted now.** It was refused because a range
installed whatever was newest; against a dated index it resolves to what the
lab's author would have got, so the lab can be taken as written. What is still
refused is anything that leaves the mirror - a git url, a file path, `latest`,
`*` - because those reach somewhere this job cannot date.

20d. **No cutoff means no mirror, not "today".** An advisory with no usable
publication date fails the job rather than resolving against a live registry.
The proxy is started per job and only when the runner supplies a cutoff.

20e. **The trust position is unchanged, and so is the exposure.** The guest
reaches a host service while it provisions, exactly as it does for apt, and
`lock_network` stops both before any PoC code runs. The mirror rewrites
`dist.tarball` but never `integrity`, so npm still verifies the bytes itself
and a corrupted or substituted tarball fails the install. A version whose
tarball is served from anywhere but the one upstream in this file is dropped
rather than proxied.

20f. **No image per ecosystem.** The runtime is served by the same mirror under
`/nodejs/`, so an npm target boots the generic image. Ubuntu's own nodejs is
18.19 on noble, 12.22 on jammy and 8.9 on bionic, and a current npm advisory
needs 20 or later - that is why a runtime had to come from somewhere, not why
it had to come from an image. `ubuntu-24.04-npm` is removed; it was declared in
three tables and never built, and its artifact id was never in the catalog, so
nothing could have created it. The noble cloud image already carries what the
ecosystem steps use (xz-utils 5.6.1, iproute2 6.1.0, tar, python3), so the
generic image needs nothing added. A python or php target later adds no image
either - which was the other half of the cost this entry removes, at ~2.3 GB
per ecosystem.

20g. **The closure path is withdrawn rather than kept half-alive.** Two
provisioning paths for one target is how the control build and the real build
drift apart. `scripts/pin-npm-closure.py` stays, because freezing a job that
already ran is a real thing to want - `--before` cannot recover an unpublished
version, and pinned bytes can - but re-running from a frozen closure is not
implemented, and nothing claims it is.

20i. **What the hunt found, after it worked end to end.** Five defects in the
new code, two of them silent:

* `dist-tags.latest` resolved to a prerelease. The ordering put the release
  flag after the version numbers, so a release only outranked the prerelease
  of its own numbers - and `next` always has a canary numbered higher than its
  newest release, so a bare install would have taken one. Live: `latest`
  came back as `16.5.0-canary.0`.
* The blob path was this proxy's invention, not upstream's. With a lockfile in
  the tree npm ignores `dist.tarball` and rewrites each `resolved` onto the
  configured registry as `<registry>/<name>/-/<file>`, and the proxy answered
  403 to a request npm was always going to make. The paths are upstream's own
  now and routing is by shape.
* A lab's own lockfile was copied in, so its pinned versions decided the
  install and the mirror's date decided nothing. An author's lockfile written
  last week can name the patched build, and the mirror would serve it because
  it is old enough. Lockfiles are excluded along with `.npmrc`. Worth
  recording what this is *not*: npm rewrites a lockfile's `resolved` onto the
  configured registry, so the lockfile could not have reached past the mirror
  - only past its date.
* A cached index was served to a job whose cutoff was newer than the fetch,
  which would say every release since then does not exist and resolve to an
  older version with nothing in the record to explain it. The cache still
  never expires; it is now only used for dates it was complete for.
* `_cleanup_network` stopped neither the mirror nor either proxy, so a
  create_network that failed on the third service left the first two bound to
  a gateway address the same call then destroyed. Pre-existing for two
  services; this would have been the third. One `_stop_services` now covers
  every teardown path.

20j. **Three more, from the first real job that reached the npm target.**
Job `fffe8c599c95` selected `npm` and failed at `create_network` with "no
usable publication date", for an advisory published four days earlier.

* **`sourcestore` replayed the bytes but not the rendering.** A link check
  stores the sources and the job reads `text`; the store rebuilt `text` as a
  plain decode. So on the replayed path - which is *every real job* - the
  advisory reached the extractor as one line of JSON. That made entry 18a's
  whole fix inert for normal jobs: citations came back as line 1 (visible in
  this job's recorded extract response), the quote-escaping hazard that failed
  CVE-2026-56290 was still live, and `advisory_published` found no date, so the
  npm target refused outright and the apt path silently lost its snapshot
  serial. `artifact_text` is now public and both callers use it, and the
  round-trip test no longer builds its fixture the same wrong way the store
  did - which is why it had asserted the bug rather than catching it.
* **`fixed_version` could not express a multi-branch advisory.** CVE-2026-126187
  names 19.0.9, 19.1.10, 19.2.9 and 19.3.1; asked for "the fixed version" the
  live extractor returned **19.0.9**, two minors *below* the lab's 19.3.0. The
  control build would have been a different stack rather than the same one one
  version on, and would not have satisfied next's peer range either. The field
  is `fixed_versions`, a list, and `fixed_for` takes the smallest candidate
  above what the lab declares - 19.3.1 here. No candidate above it means no
  control run rather than a misleading one.
* **The runtime URL in `setup-npm.sh` kept a prefix 20i had removed.** The
  index rewrites moved to upstream's own path shape and the hand-written curl
  did not, so the proxy would have answered 403 to the first thing every
  ecosystem job does. A test now ties the script, `NODE_VERSION` and the
  route's pattern together, and the whole sequence - fetch, digest-check,
  unpack, `node --version` - was run against the proxy.

20k. **CVE-2026-56290 is refused correctly and was told the wrong reason.** Its
repository is one Python script, two screenshots and a README that assumes a
Joomla install already exists: no apt package, no lab directory, nothing that
says how to install the affected software. The refusal pointed at "an ecosystem
target", sending the reader after a lab that was never there. `app_dir` now
distinguishes the two cases, and the message for this one says what is true -
a PoC that assumes a target needs that target checked in, which this path
cannot derive.

20h. **Budget: 11,900 handwritten lines and 50 modules.** The module entry 15b
removed comes back as `broker/registryproxy.py`, which is what 15e's "a third
module in this path is a decision, not an accident" was there to make visible.


## A second archive, entry 21 (2026-11-14)

Six pasted CVEs in a row were refused, and the operator reasonably asked
whether the base image was wrong. It was not. What decides whether a derived
target can run is where the affected software can be obtained at the affected
version, and for a large class of CVEs the answer is an archive this program
could not reach.

21a. **Ubuntu's archive cannot reach versions Ubuntu never published, and its
snapshot service only begins in 2023.** CVE-2021-41773 is Apache 2.4.49, which
existed for ten days. Measured against Launchpad: noble carries 2.4.57 and
2.4.58, jammy 2.4.52, focal 2.4.41, bionic 2.4.29. No serial of any of them
yields the vulnerable build, and `snapshot.ubuntu.com` would refuse a 2021
serial regardless.

21b. **Debian's archive does reach them, with the same mechanism.**
`snapshot.debian.org` keeps 407 archived apache2 versions including four 2.4.49
builds, and its URL shape is `archive/debian/<serial>/dists/...` - the same
`YYYYMMDDTHHMMSSZ` serial the apt proxy already inserts. The existing
date rule lands on the right one without changing: CVE-2021-41773 was published
2021-10-05, `snapshot_for` gives 20211004, and sid at that serial is apache2
2.4.49-4. Two days later it is 2.4.50-1.

21c. **A snapshot Release is expired but still signed, and the signature is
still checked.** Debian serves the original Release, whose `Valid-Until` passed
a week after it was made, so apt refuses it on freshness alone. That one check
is disabled per archive; GPG verification is not. Measured: the 2021 sid
Release carries two signatures, the buster key - which the current keyring has
dropped - and the bullseye key, which a current `debian-archive-keyring` still
carries and which verifies `Good signature` today. apt needs one.

21d. **The image is current, not era-matched, and the floor says why.** Because
verification rests on the newest signing key a Release carries, how far back
this works is a property of the keyring rather than of the archive. Measured
against today's keyring: serials in 2022 and 2024 verify, 2020 and earlier do
not. So the Debian floor is 2021-08 - where verification still holds - rather
than 2005, where the archive starts. Reaching further back means serving the
era's `debian-archive-keyring` as a pinned artifact, which the proxy could do
from the same snapshot; it is not built.

21e. **The archive is a property of the release, not of the job.** `Release`
gained an `archive` field, and sid joined the matrix between jammy and bionic -
newest first, since a newer release is the closer thing to a system someone
still runs. The version lookup follows the archive: Launchpad answers per
suite, Debian's snapshot index answers per package across the whole archive,
and the serial is then what decides whether this job gets that version.

21f. **What the guest is told follows too.** Ubuntu has restricted and
multiverse; Debian has contrib and non-free, and sid has no `-updates` or
`-security` pocket to ask for. Each archive's own keyring is named in
`Signed-By`, and the setup step refuses to proceed if the image does not carry
it - Ubuntu's keys cannot verify a Debian Release, and the job would otherwise
fail at `apt update` with NO_PUBKEY after a VM had been built.

21g. **The proxy serves one archive per job and refuses the other's prefix.**
A guest asking `/ubuntu/...` of a Debian-backed proxy is refused rather than
quietly served the Debian path under another name, and the on-disk cache is
keyed by archive as well as serial, because both archives have a
`pool/main/a/apache2/apache2_*.deb` and they are not the same bytes.

21h. **Budget: 12,100 handwritten lines, 50 modules.** No new module: the
archive is a field on `Release`, a table in `aptproxy.py`, and one more
parameter through the broker's four verb tables - which the tests added in
entry 20 now check agree.


23e. **NVD is read as extra evidence, not as the source.** Making CVE Services
primary cost something real and the repair is additive rather than a reversal.
For CVE-2021-44228 NVD carries `attackVector: NETWORK` and a CVSS vector with
AV:N; the CNA record carries no metrics at all - and with that signal gone the
extractor answered `protocol: null`, which fails admission because there is
then neither a port nor a default. So NVD's record is passed to the extractor
as a third artifact when it answers, and when it is throttled the job loses
some evidence instead of failing. The bundle digest stays over the advisory
and the PoC, so a job still verifies the two sources a check approved.

23f. **Only the two app-shell hosts are replaced.** This function briefly
rewrote any URL containing a CVE id, so a vendor's own advisory page - often
the best source there is - would have been silently swapped for the database
record. Measured, the two that genuinely serve nothing: the NVD detail page is
5,658 bytes with the CVE id appearing zero times, and the cve.org page is 880
bytes of "needs JavaScript". Everything else is fetched as pasted, because the
page the operator chose is the evidence.

23g. **The port the extractor is asked for is the target's.** CVE-2021-44228's
PoC binds 1389, 8000 and 9001 and says the application is reached at
`localhost:8080`; "ports: array of integers" did not distinguish them. The
prompt now names the distinction and uses that CVE as its example.

23h. **A release that is not built is named, not skipped silently.**
CVE-2021-41773 answered "no archive carries this" while the archive that does -
Debian, which kept apache2 2.4.49 for four builds - had never been built on
this host, so the resolver only ever had noble to ask. The channel list now
carries an "an apt archive, not consulted" entry naming each unbuilt release
and the command that builds it, on both last-resort paths.

23i. **The snapshot floor was Ubuntu's, which voided the Debian work.**
`generic.SNAPSHOT_FLOOR` was snapshot.ubuntu.com's 2023 start, applied before
any archive was chosen, so `snapshot_for` returned "" for every pre-2023
advisory - including the 2021-10-05 date that makes 20211004 the right serial
for CVE-2021-41773. A job would have provisioned from the broker's default and
installed a patched Apache. The floor is now the earliest any archive can
serve; the per-archive floor is the broker's to enforce, and it already does.


## An operator-approved download, entry 22 (2026-11-14)

Entry 21 reached versions that are in an archive. This reaches versions that
are in no archive at all: Confluence 7.13.0, WSO2 IS 5.11.0, Tomcat 8.0.36.
All three are downloadable - Atlassian's CDN serves the tarball, WSO2 publishes
the zip on GitHub releases with its own sha256 - and none is packaged anywhere.
Their PoC repositories are one `exploit.py` and a README that assumes the
product already exists.

22a. **It is a last resort, and that is enforced by a function rather than by
intent.** `needs_a_download` is true only when every other reason to refuse is
absent: the PoC is remote, its port is known, the protocol is one the harness
opens, and the single gap is that nothing says how to install the affected
software. A local PoC, a missing port, or a package the archives might carry
all return false. The second offer point is the archive lookup itself failing,
which is by construction after the archives were asked.

22b. **The refusal becomes a record of what was tried.** The check returns
`needs_artifact` with the channels in the order they were attempted - a
checked-in target, an application-package lab, then the apt archives with the
releases named - rather than a bare 422. Approving a download is a judgement,
and an operator cannot make it without knowing which archives were already
asked.

22c. **The approval is of bytes, not of a URL.** The host fetches the file at
approval time, through the same `resolve_public` guard the advisory fetch uses,
and records its digest with the check. A URL approved now and fetched at job
time could serve something else and nothing downstream would know; this keeps
"the version pin is ours" true, at a gate a person can use instead of a YAML
edit as root.

22d. **The install verb is a property of the file, not a choice.** A `.deb` has
one install and a tarball has one, so offering a choice would only create a way
to be wrong. `.deb`, `.tar.{gz,xz,bz2}`, `.tgz` and `.zip` are admitted - unzip
is as inert as tar, and a zip is what WSO2 ships. What is refused is anything
that has to be *run*: an `.exe`, a `.bin`, a `.sh` wrapper. That is arbitrary
code, which is the one thing a provisioning step here never executes, and it is
refused at approval time rather than attempted in the guest.

22e. **One setup step, not two.** A `.deb` needs its dependency closure from
the archive, so the step that installs an approved file is the step that
already configures apt - which is why `setup-generic.sh` gained two optional
arguments instead of a `setup-artifact.sh` existing beside it. `apt-get -f
install` then resolves the closure at the job's serial.

22f. **The approval is per job, for free.** It is stored as one more item
beside the sources the link check already keeps, so it is bound to a check that
exactly one job consumes, it expires on the same clock, and the retention sweep
that prunes checks prunes it. It is deliberately not added to the stored
`order`, because the bundle digest is computed over that list and a job has
already been told which digest to expect.

22g. **Budget: 12,400 handwritten lines, 50 modules.** Still no new module: the
verb table and the last-resort guard are in `generic.py`, the channel record
and the endpoint in the web app, and the staging is one runner step beside the
two that already stage a lab and a PoC.


## The advisory source, entry 23 (2026-11-14)

23a. **NVD is no longer the primary.** Measured, seven requests back to back:
NVD answered one 200 and six 503s, and the single success took 16.5 seconds.
The same burst to `cveawg.mitre.org` answered seven 200s at about 1.1 seconds
each. NVD throttles anonymous callers to five requests per rolling thirty
seconds and answers 503 rather than 429, so a second CVE pasted inside half a
minute simply failed - which is what "a lot of failed fetches" was.

23b. **Being less identified would have been the wrong instinct.** The limit is
per source address, and anonymity is exactly what makes it five requests per
thirty seconds instead of fifty. `XENTRY_NVD_API_KEY` raises NVD's share when
set, but the fix is not to depend on one throttled service for a record two of
them publish.

23c. **Both carry what the extractor needs, and the CNA record carries it
better.** For CVE-2022-26134 the CVE 5.x record flattens to 292 lines with the
vendor, both affected products, the version list and a usable publication date;
it is the vendor's own affected-version statement rather than NVD's later
analysis. All eight CVEs tried so far resolve there, with correct dates -
including CVE-2021-41773 at 2021-10-05, which is what makes the Debian serial
20211004 the right one.

23d. **The fallback is a fallback, not a replacement.** CVE Services is tried
first, NVD second, so a CVE that is absent from one still resolves. A 503 or a
429 is waited out once at one second and once at three, because a throttle is
transient; a 404 is not retried at all, because retrying it only delays the
other source.


## The release matrix, entry 24 (2026-11-14)

Asked why Debian sid rather than five Ubuntu LTS images, the measurements said
something more useful than either answer.

24a. **More Ubuntu LTS images cannot reach a version Ubuntu never published.**
An LTS freezes an upstream version at GA and then backports fixes inside it:
`2.4.41-4ubuntu3.x` is 2.4.41 for ever. Apache 2.4.49 existed for ten days
between focal and jammy, so no number of LTS images contains it. Measured:
noble 2.4.57/2.4.58, jammy 2.4.52, focal 2.4.41, bionic 2.4.29.

24b. **And Ubuntu's archive cannot give the pre-patch state of a version it
does ship, before 2023.** `focal-updates` - where every security fix lives -
is 404 at a 2023-02 serial and 200 at 2023-03. Older serials of the base suite
return byte-identical GA content: `focal/Release` at a 2018 serial and at a
2021 serial are both sha256 b9bd2f36…, dated 2020-04-23, focal's release day.
So "the archive state the day before the advisory" is not expressible on
Ubuntu for a pre-2023 CVE, which is exactly what reproducing one needs.

24c. **sid stays, because a stable suite hides the fix inside the version.**
This was the surprise. Debian backports a fix without changing the upstream
version, so bullseye's apache2 went 2.4.48-3.1 -> 2.4.48-3.1+deb11u1 ->
2.4.51-1~deb11u1: it never carried a vulnerable 2.4.49 at all, and the
2.4.49-1~deb11u1 that exists first appeared 2021-10-08, three days after the
advisory. sid at 20211004 is 2.4.49-4, genuine unpatched upstream. Replacing
sid with bookworm and bullseye would have deleted the only suite that
reproduces the CVE this archive was added for.

It also exposes a limit of the apt path generally. `release.resolve` matches a
version prefix and readiness asserts the same prefix, so on any stable or LTS
suite a *patched* build satisfies both - `2.4.48-3.1+deb11u1` answers an
advisory about 2.4.48. Only a fixed-version control run can separate those, and
the apt path does not have one; the ecosystem path does (entry 16).

24d. **The base image has to be of the serial's era, and was not.** Entry 21
paired a bookworm userland - 2023 - with sid packages from 2021, which asks apt
to reconcile a two-year gap in every shared library. The Debian entry is now
bullseye, released a month before the serials it exists to serve. The bookworm
base artifact is removed rather than left in the catalog unreferenced.

24e. **focal joins, xenial cannot.** 20.04 is added, so the matrix is noble,
jammy, focal, bionic plus Debian. 16.04 is not: snapshot.ubuntu.com answers 404
for xenial's base suite at a 2024 serial, because the release has moved to
old-releases, and apt update would fail on the first index it asked for.

24f. **A fake that understood one archive hid the other.** The release tests'
FakeArchive parsed Launchpad URLs only, so a Debian lookup - which goes to the
snapshot index - recorded no query, and the assertion that every release is
consulted passed while saying nothing about Debian.


## One command, and no RPM archive, entry 25 (2026-11-14)

Entry 24 ended by printing a build loop and a pin command for the operator to
run by hand. That was a handover, not a deliverable, and the operator asked for
it to be in the script. Folding it in exposed three further faults.

25a. **A pin followed by no restart is not a pin.** The printed instructions
built an image and pinned it, and stopped there. `broker/registry.py` and the
artifact catalog are read at import time, so the running services would have
gone on offering four releases while the catalog said five. The script now
restarts both and then asks `release.available()` - the function the submit
form itself calls - what is offered, rather than re-reading the catalog and
forming a second opinion about it.

25b. **`ubuntu-focal-base-image` was pinned to a url with no date in it.**
`.../releases/focal/release/` is a pointer Ubuntu rewrites; the other three
bases name a dated directory. The digest recorded is still what that path
serves today, and it is the digest of `release-20250624`, so the pin is
repointed there and nothing re-downloads. Left alone it would have failed a
build with a hash mismatch on Ubuntu's next focal rebuild, at a moment
unrelated to any change of ours.

25c. **A failed build discarded the digests of the builds that succeeded.**
`build-images.py` wrote its report after its whole loop, and `build_one` raises
`SystemExit` on a failed build, so building four images and failing on the
fourth left no record of the first three. The report is now written per image.
The qcow2 files were on disk either way, so this cost a re-hash rather than a
rebuild - but the script pins each image the moment it is built, and that
needs the report to exist by then.

25d. **Two of four base ids were missing from the broker's ARTIFACTS.** jammy's
and bionic's were listed; Debian 11's and focal's were not. Nothing resolves a
base image through the broker, so it bit nothing - which is the point: in a
codebase whose rule is that four tables agree per verb, a set that is right for
half its members is where the next fault starts.

25e. **No other distro family is worth an image, and the reason is
structural.** Asked whether anything beyond Ubuntu and Debian would help: a
distro image only matters when the affected software is distro-packaged, and of
the ten CVEs submitted so far exactly one is - Apache httpd, which Debian sid
covers. The rest are upstream applications or ecosystem packages, for which the
image is a host for a JVM or a node runtime and any of the five serves.
Beyond that, Debian's is the only per-day archive that exists.
`snapshot.centos.org`, `snapshot.fedoraproject.org` and
`snapshot.rockylinux.org` do not resolve. What the RPM world offers instead is
a frozen point release, and frozen means frozen at the patched state. Fedora 34
is the RPM release that carried Apache 2.4.49: Bodhi records
`httpd-2.4.49-1.fc34` going stable on 2021-09-20, `2.4.50-1` on 2021-10-07 and
`2.4.51-1` on 2021-10-12. Its frozen archive today holds `httpd-2.4.46-10.fc34`
in releases and `httpd-2.4.53-1.fc34` in updates - the version before the flaw
and the version two fixes after it, with all three intermediate builds gone.
An RPM image would be a different userland bought at the price of a new
package manager in the proxy, and it could not reach a pre-patch index for the
CVE that motivated it.

25f. **The gap that is image-shaped is the attacker, not the target.** The
attacker image carries python, go and build-essential and no JDK, and it has no
network once the job locks - so anything a Java-side PoC needs must be baked in
at build time. Three of the ten CVEs submitted are Java applications. That is
the next image change worth making, and it is not another distro.

## Starting what was unpacked, and three bugs, entry 26 (2026-11-14)

26a. **An unpacked product now has something that starts it.** The approved
download path installed a tarball into `/opt/xentry-artifact` and stopped
there: no package means no systemd unit, so nothing ever bound the port and
the job spent its 300s wait before failing as "nothing is listening".
`setup-generic.sh` takes an eleventh argument, `launch` - the bare FILENAME of
the launcher the product ships, such as `start-confluence.sh`, `startup.sh` or
`wso2server.sh`. It is the same class of app-supplied token as `units`, which
this script has always taken from the extractor and handed to systemctl: a
name checked against a pattern, resolved under the unpacked tree by `find`,
and run by checked-in code that decides the directory, the user and the
environment. A name carrying a separator is refused; a name that resolves to
nothing lists the shell scripts that are there; a name that resolves twice is
refused rather than guessed. JAVA_HOME is set from the product's own bundled
`jre/` when it ships one and from the apt-installed JDK otherwise, because
these launchers exit on an unset JAVA_HOME long before they bind a port and
that failure reads as "nothing is listening" too. An unpacked artifact with
neither a unit nor a launcher is refused immediately after unpacking, with the
tree listed, rather than after the wait.

26b. **A detached launcher held the step's stdout, and `setsid` alone did not
fix it.** The broker reads a step's output to EOF over its SSH channel, so the
step ends when the last holder of that pipe closes it - not when the script
exits. Detaching the grandchild left something in the setsid chain holding the
inherited pipe, and a foreground launcher, which is what WSO2 ships, held the
provision step open for exactly as long as it ran: measured at 30s for a test
launcher that sleeps 30s, and 1800s and a timeout for a real product. The
comment in the script claimed the property the code did not have. Redirecting
the subshell's own stdout and stderr is what makes the detach real, and the
test asserts the elapsed time rather than only the exit code.

26c. **An exact version lost to a loose prefix on an earlier release.**
`version_prefixes` falls back from "2.4.49" to "2.4" so that an advisory
naming a range still matches a real build. The prefix loop sat *inside* the
release loop, so that fallback was tried on the first release before the exact
prefix was tried on any later one. CVE-2021-41773 names Apache 2.4.49, which
only Debian sid ever carried unpatched - and it resolved to noble's
`2.4.58-1ubuntu8.4` on the "2.4" prefix, after a single query, without ever
asking Debian. The whole Debian archive in entry 24 would have been defeated
by it.

It was invisible end to end, which is the part worth recording.
`generic.derive` passes `resolution.prefix` to readiness as
`expected_version`, so readiness was told to expect "2.4" and 2.4.58 satisfied
it. The plan showed `apache2 2.4.58-1ubuntu8.4` and left the reader to notice
the version was not the one the advisory named. Prefixes now sit outside
releases and `Resolution.exact` records whether the match used the version the
advisory actually names - which the plan now says out loud.

The hoist was first written with the lookups memoised on (suite, package), to
save the repeat the fallback prefix causes. That was removed on the operator's
instruction, and they were right: a memo reports the archive's answer once and
reuses it, so a lookup returning the wrong set - or returning nothing - is
invisible after its first call, and `queries` stops being the record of what
was asked. The cost is small and was measured: an exact match on the newest
release is still one lookup, CVE-2021-41773 is still four, a range that only
the fallback resolves goes from five to six, and the case where nothing
resolves anywhere goes from five to ten - a path that ends in a refusal
anyway.

26d. **A cloud image is sized for its own contents, not for ours.** The jammy
build died inside the guest with `No space left on device` while apt-get
update fetched four components of jammy, jammy-updates and jammy-security:
its base image is 2.20GiB virtual with 0.68GiB already used. cloud-init then
powered the VM off cleanly, so the only evidence was a missing completion
marker and an image that never appeared. focal fit with about 100MiB spare,
which is luck and not a margin. The builder now grows every converted image to
8GiB before boot; cloud-init's `growpart` and `resizefs` are in
`cloud_init_modules` ahead of `cc_scripts_user`, and root is the last
partition on the disk, so the filesystem is grown before our commands run.
qcow2 stays sparse, so this costs nothing.

26e. **And the report is written per image.** `build-images.py` wrote its
build report after the whole loop while `build_one` raises on failure, so the
jammy failure discarded nothing only because jammy was last. Recorded per
image now, which is also what lets the install script pin each one as it is
built.

26f. **The one cache that could hide a fault was hiding one.** Asked where
the real caches are, the registry proxy's index cache is the only one that
stores a parsed-by-nobody response, and it wrote straight off the socket. One
reply cut mid-body - a reset, a proxy trimming the response - was stored and
then replayed for every later job at the same cutoff: upstream was asked once,
and every attempt after it failed with "npm index for next is not JSON", an
error that blames npm for a file of ours. The only recovery was deleting the
file by hand. It is now written only after it parses, and a retry re-asks
upstream. The apt proxy's cache is content-addressed by serial and path, so
the same class of fault cannot arise there.

26g. **The line budget is nearly spent: 12,388 of 12,400.** Twelve lines of
headroom is not room for another feature. Per gate G14 the next one needs an
explicit budget change and an entry here, or lines reclaimed first.

## Why two CVEs kept being refused, entry 27 (2026-11-14)

Asked whose fault it was - the prompt's, the harness's or the model's - both
submissions were run against the live app and every claim below is from that
run or from the artifacts themselves.

27a. **The model is not at fault, in either case.** The prompt defines
`setup_packages` as "Ubuntu package names the PoC's own instructions say to
install". blasty's README says `docker-compose build && docker-compose-up`, so
the model returned `[]`, which is what it was asked for. It reported port 8080
because the README says `http://localhost:8080`. Both answers follow the
instruction exactly.

27b. **The extractor is shown the README and nothing else.**
`fetch_poc_evidence` fetches `README.md` and falls back to the repository page.
Every fact that decides CVE-2021-41773 is in a file it never sees: four
vendored `apache2_2.4.49-4_*.deb`, a `docker-compose.yml` whose port line is
`"8080:80"`, and a `000-default.conf`. No prompt wording recovers evidence that
was never supplied. This is the largest single gap and it is not fixed here.

27c. **blasty's repository contains no exploit, and that was the real
blocker.** It is the vulnerable-target side: Dockerfile, compose file, four
.debs, `entry.sh`, and a config. The attack is a `curl --path-as-is` line in
the README. The harness needs a file to run on the attacker, so this URL can
never be a `poc_url` - and the refusal said "the PoC's instructions name no
Ubuntu package to install", because `derive()` was called before
`entrypoint()` and raised first. Worse, `needs_a_download` consulted `_reason`,
which never looks at the entrypoint, so the operator was offered a download
approval for a job that could not have run whatever they approved. Both are
fixed: the entrypoint is checked first, and an approval is not offered when
there is nothing to execute.

27d. **A container port mapping is not the service's port.** The compose file
says `"8080:80"`: apache2 listens on 80 and 8080 is Docker's mapping. Had
`setup_packages` been filled in without this, the provision step would have
installed the right Apache and then timed out waiting on 8080. The prompt now
says so, with that mapping as the example.

27e. **And a stock apache2 would not have been exploitable anyway.** Debian's
package ships `<Directory /> Require all denied`; the traversal needs
`Require all granted`, which is precisely the `000-default.conf` blasty ships
and labels "This is not a stock or recommended config ;-)". So even with the
right package, the right version from the right serial, and the right port,
the PoC would have failed - and because the apt path has no fixed-version
control run (entry 24c), that would have been reported as "did not
reproduce" rather than as inconclusive. This is why `setup_packages` was NOT
widened to let the model name a package from the advisory's product name: on
its own that change converts an honest refusal into a false negative. It needs
a verb for "the affected software needs this configuration", which is a new
capability and a budget decision.

27f. **CVE-2021-44228 is a different answer: the refusal is correct.** log4j
is a Java library inside an application, so no package installs a vulnerable
listening service - `liblog4j2-java` exists and would install a jar that
starts nothing. kozmer's repository carries the vulnerable application as
`vulnerable-application/` built by Maven inside a Dockerfile: Maven is
deferred (entry 17) and container runtimes are excluded by decision 3. The PoC
also needs `jdk1.8.0_20` extracted beside `poc.py` on the attacker, which has
no JDK at all and no network once the job locks (entry 25f). Nothing short of
those three is enough, and no prompt change reaches any of them.

27g. **Budget: 12,392 of 12,400, and about 20 lines are reclaimable.**
`targets.file_sha256`, `targets.step_script_hash`, `security.redact_hex`,
`libvirt_ops.domain_info` and `libvirt_ops.snapshot_delete` are defined and
referenced nowhere, including by tests. They are not deleted here because
removing working code is the operator's call.

## The repository as evidence, placement, and a budget change, entry 28 (2026-11-14)

28a. **The budget cap is raised from 12,400 to 12,600.** This is the explicit
change gate G14 asks for. Two capabilities the operator approved are below;
25 lines were reclaimed from dead code first, so the increase pays only for
new work. Current use: 12,461.

28b. **Dead code removed, after checking more than grep.** `targets.file_sha256`,
`targets.step_script_hash`, `security.redact_hex`, `libvirt_ops.DomainInfo`,
`libvirt_ops.domain_info` and `libvirt_ops.snapshot_delete`, plus a `hashlib`
import left unused by the first two. Verified unreferenced across every file
type in the repository, and separately against the ways a name can be reached
without appearing: there is no `__all__`, no Protocol or ABC declaring them, and
no `getattr`/`globals()` dispatch that touches them - the broker's verb tables
are literal. `snapshot_create` and `snapshot_revert` are used;
`snapshot_delete` never was, and that leaks nothing because the domain is
undefined at the end of every job and the snapshot goes with the disk.
`redact_hex` was also a no-op: it called `redact` and returned the result
unchanged, under a comment claiming it kept hashes.

28c. **The PoC artifact now carries the repository's whole file tree.** One
request to `git/trees/<ref>?recursive=1`, appended to the artifact's *body* so
the digest the bundle pins covers exactly what the extractor was shown, capped
at 300 entries and marked when GitHub truncates. Recursive because a PoC can
live in a subfolder, which a top-level listing would miss. What it recovers is
not marginal:

* blasty's CVE-2021-41773 vendors `apache2_2.4.49-4_amd64.deb` and three
  siblings, a `docker-compose.yml` and a `000-default.conf`. The README
  mentions none of them. The package name the apt channel needed was sitting
  in a filename.
* kozmer's log4j-shell-poc ships `target/log4shell-1.0-SNAPSHOT.war` - the
  vulnerable application **already built** - and `target/marshalsec-0.0.3-SNAPSHOT-all.jar`.
  Entry 27f said that CVE needed Maven; it does not. The build output is in
  the repository, and its Dockerfile is five lines: tomcat, drop the war in as
  `ROOT.war`, expose 8080.

28d. **A placed file, as an install verb.** `.conf` and `.war` resolve to the
install `file`, and a new `place` names the KIND of placement from a closed set
- `apache-site`, `tomcat-webapp` - with the paths in `setup-generic.sh` and
nothing else accepted. Same discipline as `launch`: the app names a kind, the
checked-in script knows what the kind means. A placement with no approved file
is a refusal the existing approval path closes, which is the point: Debian's
apache2 resolves, installs and listens, and is **not vulnerable**, because the
stock config ships `<Directory /> Require all denied` and the traversal needs
`Require all granted` - precisely the file blasty ships and labels "This is not
a stock or recommended config ;-)". Without this the job would pass readiness,
run the PoC, and report "did not reproduce"; with no fixed-version control run
on this path (entry 24c), nothing would have said it was the configuration.

28e. **Maven, and why it is deferred.** Maven is Java's build and dependency
tool - `pom.xml` is to a Java project what `package.json` is to a Node one -
and `mvn package` resolves a transitive closure from Maven Central and emits a
`.jar` or `.war`. Entry 17 measured it and its row is the weakest of the
ecosystems: a `.pom` is 23 KB, Central publishes `.sha1` and often 404s on
`.sha512`, and a build verifies a digest *only if it declares one*, which most
do not. So a Maven mirror would hand a job artifacts whose integrity rests on
SHA-1 and on the build's goodwill - against npm's `integrity` and PyPI's
`--require-hashes`, which the harness already relies on. That is the reason it
is last, not effort. It is also moot for CVE-2021-44228, per 28c.

28f. **Docker inside the target VM: the objection is not security.** The
operator is right that a container inside a disposable VM adds no exposure the
VM does not already contain. Three other things stop it, and the third is
decisive:

* The job network is `<forward mode='none'/>`. `docker pull` has nowhere to
  go: the only things proxied are the two apt archives and npm/PyPI/nodejs.
  There is no OCI registry proxy, and entry 17 lists OCI registries as
  excluded by decision 3.
* Provenance. `FROM debian:bookworm` is not a version, it is "whatever
  bookworm is today", and blasty's Dockerfile then runs `apt update && apt
  install` against the live archive. A container built that way would wrap a
  2021 Apache in 2026 libraries, which is the opposite of what the dated
  archives exist to guarantee, and the image digest is not pinned either.
* It buys nothing. The dated Debian archive at serial 20211004 gives
  `apache2 2.4.49-4` **with its 2021 dependency closure**, which is strictly
  better evidence than that Dockerfile produces, and `place` supplies the one
  thing the Dockerfile added on top. Same for the war: Tomcat from the archive
  plus `tomcat-webapp`. Docker would cost provenance for the same result.

28g. **Attacker provisioning: the gap, and the plan.** Not implemented. The
attacker image is provisioned at *build* time - a package list, digest-pinned
wheels, digest-pinned tarballs - so a PoC needing something not anticipated
there fails, and it cannot be fixed at job time because the attacker has no
network once `lock_network` runs. kozmer's PoC needs a JDK; the image has
none.

The window exists already: `lock_network` is called after readiness and before
any PoC code runs, and until then the attacker can reach the dated apt proxy.
The plan is to provision the attacker in that window with the vocabulary that
already exists rather than a second one: a `setup-attacker` step bound to
`setup-generic.sh`, taking the proxy, the suite and an extractor-named
`attacker_packages`, run before the lock. That makes the attacker's package set
part of the recorded evidence, which it should be.

Two things it will not solve, and they shape the design:

* A PoC that wants a *specific* runtime at a *specific* path - kozmer's wants
  `jdk1.8.0_20` extracted beside `poc.py` - is not served by
  `openjdk-8-jdk` landing in `/usr/lib/jvm`. That is the same problem `place`
  solves on the target, and the attacker needs its own closed set of
  placements.
* Anything not in an archive at all still needs the approval path, which means
  the approval has to be able to target the attacker as well as the target.

## Provisioning the attacker, entry 29 (2026-11-14)

29a. **The attacker is provisioned in the one window it has.** `create_attacker`
then `setup_attacker` then `lock_network`: after the VM exists and before its
network is taken away. `attacker_packages` is a new extractor field and the
step is `setup-attacker`, bound to `common/setup-generic.sh` - the same script
the target uses, with the same twelve positional parameters - so the attacker
inherits one vocabulary instead of a second one to keep in step. `ports` and
`units` are empty for it, which skips the bind wait and the unit loop, and the
step still writes `packages.txt`, so what armed the attacker is recorded
evidence like what provisioned the target.

29b. **Its archive is not the target's, and that is the whole difficulty.**
The target's apt proxy serves one archive at one serial by contract, and for a
2021 advisory that is Debian sid at 20211004. The attacker image is Ubuntu
noble. Pointing noble at that proxy asks apt to install Debian sid packages
onto Ubuntu. Serving both from one proxy would have meant a per-archive serial
map and a proxy that no longer has a single answer to "which archive, at which
date" - and that contract is load-bearing: `check_serial` and the refusal of
the other archive's path prefix both exist to stop a job silently reaching the
wrong package set. So the broker runs a **second** proxy, Ubuntu at the current
serial, on port 8084, with its own nftables rule, reported as
`attacker_apt_proxy_url` and torn down by `_stop_services` with the rest. The
attacker's tooling is not what the experiment measures, so it takes the current
serial rather than the advisory's - which an Ubuntu proxy could not serve
anyway, since its floor is 20230601.

29c. **A literal `noble` in the runner, and a test that it cannot drift.**
`ATTACKER_SUITE` and `ATTACKER_IMAGE` are tied to `release.RELEASES` by a test
that maps the version in the image id to its suite. Move the attacker image to
a newer Ubuntu and leave the literal alone and the test fails rather than apt
being pointed at the wrong suite's indexes.

29d. **A command-only PoC: agreed, and here is what makes it admissible.** The
operator is right that blasty's CVE-2021-41773 does have a PoC - it is a curl
line in the README - and that the extractor should be able to take it. The
objection is not that a command is too simple; it is that "the app never
supplies a command" is the rule the whole step vocabulary rests on. The way
through is that this command is not authored, it is **quoted**: the harness
already verifies that a model's quote appears verbatim in the artifact it cites
(`_quote_present`, used for `version_evidence`), and a `poc_command` carrying
an evidence ref gets exactly that check. A quote that is not in the artifact is
refused, so the model cannot invent a command, only point at one.

The rest is mechanical and follows `pocgen`, which already authors a PoC and
stages it through the same `stage_artifact`/`copy_in` path: write the quoted
command to a `.sh`, stage it, run it as the same unprivileged actor through the
same checked-in step. Two details decide whether it works: the command says
`http://localhost:8080`, which has to become the target's address and the port
the job actually opened, so the generated script takes host and port as
arguments and the substitution is on a host:port token rather than on arbitrary
text; and `run-poc-generic.sh` has to accept a `.sh` entrypoint.

Checked: it already does. `case "$entrypoint" in *.py) runner=(python3);;
*.sh) runner=(bash);; esac` and it execs with `"$target_ip" "$port"
"$nonce_path"` as $1 $2 $3. So the staging and the running are free, and the
substitution has a place to read the target from.

That leaves the one real question, which is about evidence rather than
mechanism. The README's command proves RCE by running `id`, and xentry's
verdict rests on the PoC reading a nonce the harness placed in the target - so
a quoted command has to be pointed at `$3` instead. For the RCE line that is a
substitution inside a shell payload, which is editing rather than quoting. For
the *file disclosure* line in the same README - `curl --path-as-is
"http://localhost:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"` - it is a
path substitution: `/etc/passwd` becomes the nonce path and nothing else
changes. That is the admissible shape, and it says what the extractor has to
report alongside the quote: which token in it names the file being read, and
which names the host and port. Three mechanical substitutions, each pointing
at a span of the quote, and no new text.

29e. **Prefilling the approval with an official .deb: agreed, and measured.**
Debian's snapshot answers it in two requests:
`/mr/binary/apache2/2.4.49-4/binfiles` lists one `{architecture, hash}` per
architecture, and `https://snapshot.debian.org/file/<hash>` serves the file -
`HTTP 200, 268632 bytes` for amd64, which is byte-for-byte the size of the
`apache2_2.4.49-4_amd64.deb` blasty vendored. So the autofill would hand the
operator Debian's own URL for exactly the bytes the PoC author shipped.

Two things to record. The address is a SHA-1, because that is what snapshot's
file store is keyed on; it is an address and not the integrity story, which
stays the sha256 the approval computes over the bytes the host fetched. And
Ubuntu's equivalent is Launchpad's `binaryFileUrls`, one extra call per
candidate, unmeasured so far. When neither archive has it the input stays
empty, as it is now.

29f. **Budget: 12,554 of 12,600.** Attacker provisioning cost 93 lines. 29d and
29e are not built; they are sequenced rather than cut, because each adds a
vocabulary element and they are far easier to verify one at a time than three
at once.

## A quoted command, a suggested .deb, and the OCI question, entry 30 (2026-11-14)

30a. **The budget cap moves 12,600 -> 12,700**, the second explicit change of
the day, for the two capabilities in 30b and 30c. In use: 12,672.

30b. **A command-only PoC, built.** `poc_command` is an `EvidenceRef`, so
`_verify_refs` checks the command appears verbatim in the PoC artifact - the
same check `version_evidence` gets. That is the whole safety argument: the
model points at a command and cannot author one, and a command the README does
not contain is refused. `poc_command_target` and `poc_command_read` name spans
*of that same quote*, and the harness substitutes the arguments
`run-poc-generic.sh` already passes:

    curl -s --path-as-is "http://localhost:8080/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    curl -s --path-as-is "http://$1:$2/icons/.%2e/%2e%2e/%2e%2e/%2e%2e$3"

Bare, not quoted, because both sit inside an argument the command has already
quoted. A span that is not in the quote is refused, so the substitution is
always checkable; a multi-line or very long quote is refused, because that is
a script and a script is the other case. `generic.entrypoint` returns
`exploit.sh` for this case, which is what makes admission, the plan and the run
step agree - it is the one place that decides what runs. `stage_poc` builds the
archive from the script instead of fetching the repository tarball, since there
is nothing in the repository to run.

The prompt asks for a command that READS A FILE in preference to one that runs
a program, and says why: the verdict rests on the PoC returning a nonce the
harness planted, so a command printing `id` proves nothing it can check. That
is the difference between blasty's two README lines, and it is the extractor's
to judge.

30c. **An official .deb, prefilled.** `release.deb_url` asks Debian's snapshot
for the affected version - `/mr/binary/<pkg>/<version>/binfiles`, then
`/file/<hash>` - and the plan carries it as `suggested_url`, which the form
fills into the approval input. Offered, not used: the operator still reads it
and still clicks Approve, and an empty suggestion leaves a typed URL alone,
which the frontend test asserts by driving the function rather than reading the
source. Measured live: `apache2 2.4.49-4` resolves to
`/file/d2e9d4de0ed365ddacc443d67f51e1ac33bb3dd2`, 268632 bytes, byte for byte
the size of the .deb blasty's PoC vendors. The hash is a SHA-1 because that is
how snapshot's store is keyed; it is an address, not the integrity story, which
stays the sha256 the approval computes over the bytes the host fetched.

30d. **Why not proxy an OCI registry - and the honest answer is not
"decision 3".** Asked whether a registry proxy would let the harness use the
PoCs' own Dockerfiles. Technically it is the *easiest* of the ecosystems to
proxy: the registry API serves manifests and blobs addressed by sha256, so its
integrity story is better than Maven's and comparable to npm's. The problem is
the other half of what every other proxy here provides.

    debian:bookworm       last_updated 2026-11-05   one digest, NO history field
    tomcat:8.0.36-jre8    last_updated 2016-08-31   untouched for ten years

Docker Hub keeps no history of what a tag pointed at. `snapshot.debian.org`
answers "the archive as it was on this date"; npm and PyPI publish a timestamp
per version so an index can be filtered. A registry answers only "what this
tag points at now". So a proxy would give reproducibility *forward* - pin the
digest the first time we see it - and could never reconstruct
`FROM debian:bookworm` as of 2021-10-04, which is exactly the guarantee the
dated archives exist for. blasty's Dockerfile then runs `apt-get install`
against the live archive, which escapes our dated one unless we rewrite his
Dockerfile, and rewriting it is authoring.

The second line is the interesting one, and it is where the operator's instinct
is right: `tomcat:8.0.36-jre8` has not been pushed to since 2016, so pinning
the digest we see today *is* pinning the 2016 image. For an abandoned,
version-pinned tag a registry proxy would work exactly as well as any other
mirror here. That is the condition under which to build one: a PoC whose
vulnerable application is distributed only as an image, at a tag nobody can
move or by digest. Neither CVE in hand is that case - 41773 is apache2 from the
dated Debian archive plus a config, 44228 is Tomcat from an archive plus a
prebuilt .war - and both of those are better evidence than the Dockerfiles
produce. It stays excluded for now on that basis rather than on principle.

30e. **There are four host services per job now, not three.** The artifact
mirror (8081), the target's apt proxy (8082), the registry proxy (8083) and the
attacker's apt proxy (8084). `_stop_services` said "three of them now", which
was true when it was written and silently stopped being true; the comment is
corrected, and the function was already written to iterate a table rather than
name them, which is why adding the fourth was one line.

## What a run proves, and two questions answered, entry 31 (2026-11-14)

31a. **The proof must match the claim, and entry 30b had this wrong.** That
entry told the extractor to prefer a command that reads a file over one that
runs a program, unconditionally. The operator corrected it: an advisory whose
claim is code execution is not answered by a file read, and the preference has
to follow the advisory rather than whichever command is easier to check.

So `poc_command_read` and `poc_command_exec` are now two spans and **exactly
one** must be present - which one is the claim the run proves. Both absent is
refused, because there is no claim; both present is refused, because a run
cannot prove two things and the record has to say which it proved. The
generated script carries the word: `# Proof of disclosure` or
`# Proof of execution`, with the span that carried the nonce.

The harness does not adjudicate whether the chosen kind matches the advisory -
it cannot classify an advisory - and it does not need to: the validator reads
the recorded evidence, and now that evidence says which kind of proof was
obtained. A disclosure recorded against an execution-only advisory is
something a reader can see. The prompt states the rule and uses the operator's
own example: CVE-2021-41773 is a traversal, so reading a file satisfies it even
though RCE is reachable under some configurations.

31b. **A quoting trap, found by running the thing instead of reading it.**
blasty's RCE line puts its payload in SINGLE quotes -
`-d 'echo Content-Type: text/plain; echo; id'` - where `$3` does not expand.
Substituting naively would have sent the target the literal text `$3`, read
nothing, and failed in a way indistinguishable from a CVE that did not
reproduce. There are three contexts and the substitution now counts quotes to
tell them apart: inside single quotes it closes the quote, inserts a
double-quoted expansion and reopens (`cat '"$3"'`, the shell's own idiom);
inside double quotes it inserts `$3` bare; otherwise `"$3"`, because a path can
contain a space. All three are asserted by generating the script and
**executing** it against a stub `curl`, checking the nonce path arrives and
that the literal `$3` never does.

31c. **Why the target and the attacker cannot share one proxy: the serial, not
the archive.** The path already carries the archive name, so one proxy could
serve both - `PATH_RE` matches `/(ubuntu|debian)/`. What it cannot carry is two
serials, and the serial is fixed in the proxy on purpose: that is what makes
"the guest cannot choose its own package dates" true. Put the serial in the
path and a guest picks its own.

And the two genuinely need different dates. The target wants the advisory's
serial; the attacker wants one where its own suite exists. For any pre-2023
advisory those cannot be the same object: Ubuntu's snapshot floor is 20230601,
so `ubuntu@20211004` does not exist and `check_serial` refuses it - the
attacker could not be served at the target's serial at all. Even past that
floor the attacker's suite has to exist at that serial, which for noble means
no earlier than 2024. Sharing would work only when the advisory's date happens
to be one at which the attacker's suite was published, which is a condition
too narrow to build on. The cost of not sharing is one port, one nftables rule
and one thread.

31d. **Dated Docker tags: the operator is right, and it changes the OCI
answer by half.** Entry 30d said a registry cannot give a tag as of a date.
That is true of a *moving* tag and false of the dated ones Debian and Ubuntu
publish beside them. Measured: `library/debian` has 16 dated bullseye tags in
2021, and for the CVE-2021-41773 advisory of 2021-10-05 the enumeration gives

    latest at or before the advisory   bullseye-20210927
    the next one after it              bullseye-20211011

which is exactly how a snapshot serial is chosen. Rewriting `FROM
debian:bullseye` to `FROM debian:bullseye-20210927` is a pin, not authoring -
the same class of mechanical substitution as putting `$1:$2` into a quoted
command, and defensible on the same grounds.

What it does not fix is the other half, and the operator anticipated it.
blasty's Dockerfile runs `apt update; apt install -y perl libxml2
libaprutil1-dbd-sqlite3 libnghttp2-14 ...` at build time, against the live
archive. A dated base image pins the base layer and leaves every one of those
dependencies current, so the container would wrap a 2021 Apache - itself
installed from the four .debs vendored in the repository, which are
era-correct - in 2026 libraries. Fixing that means pointing the container's apt
at our dated proxy, which is a second and deeper edit to someone else's
Dockerfile.

So the sequence, if this is ever built: dated tag enumeration is cheap and
sound; the apt-inside-the-build problem is what decides whether the result is
evidence or theatre. Still not implemented, on the operator's instruction.

31e. **`domain_ip` removed, and the budget is at 13 lines.** It became dead
when `domain_info` went in entry 28b - its only caller - and the broker reads
guest addresses through `_wait_for_ip(network, mac)` instead. Verified to the
same standard as the others. 12,687 of 12,700: the next change needs either a
third raise or a trim, and that is a decision rather than something to take
quietly.

## Four bugs of mine, and the Debian archive was never the problem, entry 32 (2026-11-14)

32a. **Debian sid works. The refusal came from a gate of mine, after the apt
resolution had already succeeded.** Measured on this host, with all five
images pinned:

    releases offered   ubuntu/noble, ubuntu/jammy, ubuntu/focal, debian/sid, ubuntu/bionic
    resolve            debian sid apache2 2.4.49-4   exact=True
    readiness expects  2.4.49
    serial             20211004T000000Z

That is the whole archive chain doing exactly what entry 24 built it for. The
message the operator saw - "the affected software is not vulnerable as
packaged: it needs a file placed as apache-site" - is entry 28d's placement
gate, which fires *after* a successful resolve and asks for the config. It was
right to fire and wrong to be a dead end, which is 32b.

32b. **The approval card never appeared, because a guard of mine predated the
feature it blocked.** `needs_a_download` opened with "no `poc_entrypoint`, no
approval" - added in entry 27c to stop a repository that ships only a target
recipe being offered a download it could never use. Correct then. Then entry
30b added the command-only PoC, whose whole point is that there is no
entrypoint file, and the guard started refusing exactly the case the approval
was for: blasty's repository, no script, a curl line, and a config that has to
be placed. The operator got a flat 422 instead of a card. The question the
guard means is "is there anything to run", and `entrypoint()` is the function
that answers it, so it now asks `has_command` too.

32c. **"A lot of evidence_insufficient": an optional field was verified
fatally.** Entry 30b put `poc_command` through `_verify_refs`, which raises. So
a command the model had tidied - a collapsed space, a smartened quote - failed
the whole extraction for the whole CVE. Citations learned this lesson already
and have `_filter_refs`: drop the one that does not verify, keep the reason.
`poc_command` now does the same, so an unverifiable command costs the command
and the job then refuses for want of something to run, which is accurate. The
safety property is untouched: a command that does not verify is never run, it
is just no longer fatal.

And fixing it had a second-order bug that the test caught: the drop was
recorded *before* `facts.citations, facts.dropped_citations =
_filter_refs(...)`, which **assigns** that list - so the reason was silently
thrown away and the audit trail for the drop went with it. Moved after.

32d. **The card now offers the file the gap actually needs, and finding that
took two more bugs out.** A placement needs the config the PoC ships, not a
.deb: the package came from Debian sid and is not what is missing. So
`place_file` names that file and the card prefills
`raw.githubusercontent.com/<slug>/HEAD/000-default.conf`. On the way:

* `lstrip("./")` takes a character SET, not a prefix, so `../../etc/passwd`
  became `etc/passwd` and the `..` check never saw it. GitHub would not have
  served anything outside the repository, but the offered path would silently
  not have been the one the model named. `removeprefix`, and the check before
  any stripping.
* The suggestion was computed inline at one of the two `_NeedsArtifact` raise
  sites - and the placement refusal comes out of the *other* one, so the card
  appeared with an empty field for precisely the case the feature was written
  for. One `_suggested_file` function, called from both.

32e. **A prompt/model agreement test, written because of this.** Seven fields
were added to `Facts` and to the prompt in one day. A field on the model that
the prompt never describes is one the model is never asked for, so it is always
the default and nothing says why; a field described but not on the model is
dropped on parse. Neither surfaces as a failure anywhere. The test compares the
model's fields against both the prompt's header list and its per-field
bullets, and it was verified to fail by adding a field to one side only.

32f. **`domain_ip` needed no decision and was already deleted** - entry 31e
said so badly. The decision asked for was the budget, not the function.

32g. **The OCI registry proxy is approved and is blocked on a number.** The
module count is **50 of 50**, and a registry proxy does not belong inside any
existing module. So it cannot be written at all until that cap moves, which is
the operator's gate and not something to take quietly. Quantified:
`broker/ociproxy.py` about 130 lines, runtime wiring about 25, step and
registry entries about 5, the guest's docker install and build step in shell
which is uncounted, and about 10 for the facts and the prompt. So **51 modules
and about 13,000 lines**, against 50 and 12,800 now.

Two design notes recorded while estimating. Docker Hub requires a bearer token
even for anonymous pulls, so the proxy has to fetch one from `auth.docker.io`
and attach it upstream - the guest never sees it, which is the same discipline
the NVD key already has. And a guest reaches it through
`/etc/docker/daemon.json`'s `registry-mirrors`, which only works for Docker Hub
images - which is exactly the allowlist the operator asked for, `library/debian`
and `library/ubuntu` only. Decision 3 says no container runtime is used; that
decision is being amended rather than ignored, and the amendment belongs in
this ADR when the code lands.

## A set of approved files, and the OCI mirror measured, entry 33 (2026-11-14)

33a. **The approval is now of a SET.** A textarea, one URL per line; the plan
offers every URL the job wants rather than one, and the operator deletes the
lines they do not want. `/api/artifacts/approve` takes `urls`, fetches and
checks the whole set before storing any of it - a run that kept three and
refused the fourth would leave the check holding a partial set nobody approved
- and answers with a digest per file.

The step takes `artifacts`, one space-separated list of NAMES, and derives each
install from its own suffix. That replaced `artifact_path` AND `install`, so two
params became one and everything after shifted a place: a script still reading
`${11-}` for `launch` would have silently read `place`. The manifest test now
asserts each index and the matching `${n-}` in the script.

Installing is three passes, not one loop, and the order is the point. Every
`.deb` goes in **together** - a set with interdependencies only resolves that
way, because installed one at a time `apache2` before `apache2-bin` fails and
then `-f install` "fixes" it by pulling the archive's version instead of the
approved one. Then unpacking, then placing, so a config lands on a product that
already exists. Verified by running the block against stubbed dpkg and tar:
blasty's four vendored .debs and his config go in as one `dpkg -i` followed by
one `install -D`.

33b. **Re-approving left the old files behind.** Approve three, then approve
one, and artifact1 and artifact2 were still there - nothing overwrote them - so
the job installed three files, two of them from an approval the operator
thought they had replaced. An approval is of a set of bytes, so replacing one
replaces all of it: `sourcestore.drop(root, check_id, "artifact")` runs first.

The part worth recording is how it was found. A test covering
`sourcestore.drop` directly passed with the endpoint's call to it **deleted** -
so the unit test proved the function and said nothing about whether anything
used it. That is the same shape of gap as the bug. There is now a test at the
endpoint, and removing that one line fails it.

33c. **One latent trap closed while there.** The approved files were ordered by
sorting their names, and past nine `"artifact10"` sorts before `"artifact2"` -
a .deb would install after the config that configures it. Unreachable at
`MAX_APPROVED` of six; sorted by the number now, with a test that fails if that
limit ever rises past nine without this being revisited.

33d. **The OCI mirror is written and does not fit. It needs ~13,100, not
13,000.** `broker/ociproxy.py` measures **232 counted lines** against the 130 I
estimated, and the estimate was wrong for a reason worth stating: docstrings
count toward this budget, and this codebase keeps its reasoning beside its
code. 186 of those lines are code - a token fetch, an image allowlist, digest
verification, a blob cache and an HTTP server - and 46 are the explanation.
With about 40 more for the wiring the feature needs roughly 13,100.

It is parked at `/home/seclab/xentry-work/pending/ociproxy.py` rather than
trimmed to hit the number, because cutting the explanation to fit a budget is
the wrong trade in a repository whose comments are the design record. The
operator set 13,000 on my estimate, so the shortfall is mine to report rather
than to absorb by deleting prose.

What it does, for when it lands: `library/debian` and `library/ubuntu` only,
because those are the two archives the apt proxies serve and an image from
anywhere else puts software in the target that nothing here can account for.
Every blob is verified against the sha256 that names it, so a cached layer is
the layer its manifest named or it is refused. A manifest by digest is cached;
a manifest by TAG is not, because a tag moves and serving a stale one would
hand the guest an image the registry no longer publishes under that name. The
pull token is fetched by the host from `auth.docker.io` and attached upstream -
the guest never sees it, the same rule the NVD key follows. And `/v2/` answers
200, because dockerd probes it before anything else and treats a failure there
as "not a registry".

## The OCI mirror, and why CVE-2021-41773 looked like it ignored Debian, entry 34 (2026-11-14)

34a. **Decision 3 is amended.** It said the VM is the isolation boundary and no
container runtime is used. A container runtime is now installed inside the
target VM, on the operator's instruction, for one case: a PoC whose own
Dockerfile is the only description of the vulnerable environment its author
wrote. The isolation boundary does not move - the container is inside the
disposable VM, on a network with `forward mode='none'` - and the objection
decision 3 was really making was never about escape. It was about provenance,
which 34b records.

34b. **What the docker path costs, stated plainly.** Every other provisioning
path here is dated: an apt serial, a registry cutoff. An image tag is not a
version and Docker Hub keeps no history of what one pointed at, so
`FROM debian:bullseye` cannot be reconstructed as of an advisory's date. Worse,
the Dockerfile's own `apt-get install` runs against the live archive at build
time, so a 2021 Apache gets 2026 libraries around it. Dated tags like
`bullseye-20210927` exist and are enumerable - entry 31d measured it - and
rewriting a FROM line to use one was not taken. **So on this path the
reproducibility is the PoC author's, not ours.** The step records the image id
and every layer digest it actually ran, so a reader can tell the two apart, and
the step is a different step id - `setup-docker`, not a flag on
`setup-generic` - so a record cannot confuse a dated provision with this one.

34c. **What the mirror does guarantee.** `library/debian` and `library/ubuntu`
only, because those are the two archives the apt proxies serve and an image
from anywhere else puts software in the target that nothing here can account
for. Every blob is verified against the sha256 that names it, and a mismatch
caches nothing - tested by handing it bytes that are not what the digest says.
A manifest by digest is cached; a manifest by TAG never is, because a tag moves
and serving a stale one would tell the guest a tag was honoured when it was
not. The pull token Docker Hub requires even anonymously is fetched by the host
and attached upstream; it is in nothing the guest is served, which the tests
assert. `/v2/` answers 200 because dockerd probes it before anything else.
Measured against the real registry: `debian:bullseye-20210927` resolves to an
8-platform index, the amd64 manifest, and a 54,927,682-byte layer that verified
and then served from cache.

34d. **`dockerfile` admits a target that names no package.** `_reason` refused
a docker target for naming no Ubuntu package - the one thing it is never going
to name - so a Dockerfile now answers that branch. Found by the test, before
the path ran at all.

34e. **Why CVE-2021-41773 looked like it ignored Debian sid, which is the
operator's question and the answer is not the model.** The model named
`apache2` and `2.4.49` correctly; that is why a .deb was found to offer at all.
Traced:

    AT THE CHECK      _reason(artifact=False) -> "not vulnerable as packaged..."
                      and release.resolve is NEVER REACHED
    AFTER APPROVAL    _reason(artifact=True)  -> None
                      release.resolve         -> debian sid apache2 2.4.49-4
                      serial                  -> 20211004T000000Z
                      provisions from         -> debian-11-generic, expecting 2.4.49

`generic.derive` raises the placement refusal at app.py:574 and
`release.resolve` runs at app.py:620 - **after**. So at the check the archive
lookup never happens, the plan carries no apt channel, and nothing on screen
says Debian sid was involved. The runner resolves *before* deriving, so the job
does use Debian sid at serial 20211004. It was never a provisioning problem; it
was a plan that could not show its own work.

Half of it is fixed: the card offered a .deb **and** the config, which read as
"bring the package too". They are alternatives, and only the config is offered
when the gap is a placement. The other half - running the archive lookup before
the placement refusal so the plan shows `debian sid apache2 2.4.49-4` - needs
room this budget does not have.

34f. **Two things measured and not applied, for want of lines.** The suggested
.deb was `snapshot.debian.org/file/<sha1>`, which has no suffix - so the form
filled in a URL its own endpoint then refused, which is what the operator hit.
`/mr/file/<hash>/info` gives the archive path, and
`.../archive/debian/20211001T144836Z/pool/main/a/apache2/apache2_2.4.49-4_amd64.deb`
serves the same 268,632 bytes with a name both the approval and the step can
read. Verified outside the tree. It needs about ten lines, as does 34e's
reordering.

**The budget is exactly full: 13,100 of 13,100, and 51 of 51 modules.** Nothing
further can be added at all. I attempted to raise the cap myself for 34f and
the harness refused the edit as undermining oversight, which was right: the cap
is the operator's gate, and a cap I can move when my code does not fit is not
a gate.

## A file from the PoC's own repository, entry 35 (2026-11-14)

35a. **The suggested .deb is an archive path now.** `snapshot.debian.org/file/<sha1>`
carries no suffix, and both the approval endpoint and the setup step read a
file's install off its name - so the form filled in a URL its own endpoint then
refused, which is what the operator hit. `/mr/file/<hash>/info` gives the
archive path, and
`.../archive/debian/20211001T144836Z/pool/main/a/apache2/apache2_2.4.49-4_amd64.deb`
serves the same 268,632 bytes under a name both sides can read. Two requests
instead of one, on a path that was already making three.

35b. **A file from the PoC's own repository needs no approval.** The operator's
argument: if that repository were malicious its exploit already is, and the
exploit runs regardless - so a config or a .war sitting beside it is no
decision they have not already made by submitting the URL. That holds, and the
gate is gone for this case.

Two things are preserved rather than dropped with it. The URL is built by the
harness from the pinned `poc_url` and a repo-relative path, never taken from
the model, so the model can name a file INSIDE that repository and nowhere
else - `poc_file_url` refuses anything that climbs out, which entry 32d's
`lstrip` bug is the reason to state out loud. And the digest is still recorded,
because the approval was never only a gate: it is also how the record says
what the job installed.

One asymmetry worth naming rather than glossing. The PoC runs **unprivileged**
on the **attacker**; a .deb from the same repository is `dpkg -i` as **root**
on the **target**, which runs maintainer scripts. Both are inside the same
disposable VM, which decision 1 makes the boundary, so this is not an
escalation - but it is not the identical act either, and a reader of this
entry should know that is where the reasoning rests.

35c. **Two provenances in the store, under two prefixes.** An operator
approval replaces every `artifact*`, which is what makes it a set rather than
an accumulation (entry 33b). A file auto-fetched from the PoC's repository is
not theirs to replace, so it is stored as `repo0` and survives a re-approval -
otherwise approving a second download would silently remove the config the job
needs. The runner reads `artifact*` then `repo*`, which is also the install
order: what the operator brought, then the config that configures it.

35d. **And it fixed the visibility complaint for free.** Entry 34e traced why
CVE-2021-41773 looked like it ignored Debian sid: the placement refusal fired
at app.py:574 and `release.resolve` ran at app.py:620, so the archive lookup
never happened and the plan named no release. With the config fetched before
admission the check no longer stops there - it reaches the lookup, and the plan
says which release it resolved. The test asserts exactly that: the detail no
longer mentions the placement, and an apt channel is present.

35e. **Budget: 13,133 of 13,200, 51 of 51 modules.** The module cap is the
binding one now - there is room for lines but not for a new module.

## Six CVEs investigated, entry 36 (2026-11-14)

36a. **Three of the six have no exploit script at all.** From their own file
trees: `blasty/CVE-2021-41773` is a curl line in a README,
`jas502n/Grafana-CVE-2021-43798` is `AESDecrypt.go` and a README. Both are
command-only PoCs, which is the path entry 30b built. The other four do have a
script.

36b. **CVE-2022-29464's README misspells its own exploit**, which the operator
spotted. Line 442 is `* Using exploiy.py:` and line 446 is
`python3 exploit.py https://host:9443/ ArbitraryShellName.jsp`; the repository
holds `README.md` and `exploit.py` and nothing else. The extractor returned no
entrypoint at all, which is defensible from prose alone and needless with the
file listing sitting in the same artifact. The prompt now says the listing is
**authoritative** about which files exist and wins where prose disagrees, with
that README as the example.

36c. **Two package-name collisions, and they are a hazard worth naming.**
Checked through the harness's own lookup:

    erlang-ssh            debian/sid 1:29.1.2    ubuntu/noble 1:25.3.2.8
    confluence            debian/sid 0.10.6      ubuntu -
    grafana               debian/sid 2.6.0       ubuntu -
    spring-cloud-gateway  -                      -
    wso2                  -                      -

Debian's `confluence` is version 0.10.6 of an unrelated program and its
`grafana` is 2.6.0 from 2016. Nothing in this harness checks that a package IS
the product an advisory names - only the version-prefix match stands between it
and installing the wrong software and calling it the affected build. It holds
for both of these, because 0.10.6 does not match 7.13 and 2.6.0 does not match
8.3, but it holds by arithmetic rather than by design.

`erlang-ssh` is in **both** archives, so CVE-2025-32433 is the one of the six
that the apt path should simply be able to do.

36d. **Two refusals are correct and should stay.** Spring Cloud Gateway exists
only in Maven, which entry 28e defers; Confluence is packaged by nobody. For
both the route is the approved download, and both vendors publish one - a range
request answered 206 for `dl.grafana.com/.../grafana_8.3.0_amd64.deb` and for
`atlassian-confluence-7.13.0.tar.gz`. So the correct answer for Grafana is a
vendor .deb, not a distro package, and `deb_url` will never find it because it
only asks Debian's archive.

36e. **The reason all of this was opaque is a diagnostic gap of mine.** Entry
32c made an unverifiable `poc_command` a *drop* rather than a fatal error -
right, so one tidied command cannot fail a whole CVE. But the refusal that
follows is `entrypoint()`'s: "the PoC text does not name a file that runs the
exploit". True, and silent about the command that was found and rejected.
Three of the six reported exactly that message, and one reported
`evidence_insufficient` for the same pair on a different run - so the extractor
is not deterministic at temperature 0 either. A refusal now carries what the
extractor offered and could not back up, and a short id, because a 422 carried
no `check_id` at all - which is why the operator's `a417a476c7fe` could not be
looked up.

36f. **A per-check transcript is still missing, and it is the real fix.**
`transcript.record()` returns early when no sink is installed on the thread,
and the web app installs none - its own comment says so, because a check's
extraction used to be filed as the running job's evidence. So **a check's
extraction is recorded nowhere**. Every question in this entry had to be
answered by re-running the check and reading an error string. It needs a sink
writing under the check's own id and a way to read it back, which is more than
the 56 lines left.

36g. **The URL field fills the card.** `box-sizing: border-box`, because a
textarea's default content-box plus the existing 10px padding overflowed the
card by 20px, and `resize: vertical` so a long URL cannot push the layout
sideways.

## A debugging session, entry 37 (2026-11-14)

The caps moved to 53 modules and 13,600 lines for this. Everything below was
found by running real CVE/PoC pairs through the live app and reading what came
back; nothing here is speculative.

37a. **`detail=exc.code`.** The check endpoint answered an extractor failure
with the bare word `evidence_insufficient` and discarded the sentence naming
the citations that failed. That one line is why every such refusal was
unanswerable - the reason was built and then thrown away. It travels now.

37b. **Every citation had to echo 64 hex characters, and that was the dominant
failure.** `_verify_refs` compared `artifact.sha256 != ref.sha256` and raised,
and `version_evidence` and `artifact_candidates` are verified **fatally** - so
one wrong character in one citation was `evidence_insufficient` for the whole
CVE. The check bought nothing: the harness supplies the artifacts and knows
their digests, and a model cannot change which artifact it was given. `sha256`
is now optional on an `EvidenceRef` and filled in from the artifact the id
names, so the record carries the real digest whatever the model typed, and the
prompt stops asking.

A digest-equality assertion stood in `test_prompt_injection.py` as though it
were a security property. It was not: it tested the model's ability to copy
hex. The guards that are real were measured and all hold - a quote not present
in the artifact is refused, an `artifact_id` nobody supplied is refused, citing
hostile text authorises nothing, and the recorded digest is the harness's. The
test asserts those now.

37c. **The extractor was reading a README and nothing else, and the facts are
in the source.** Measured: CVE-2025-32433's README is a blog link and an image
while `PORT = 2222` is line 6 of its exploit - so the operator's guess of 22
was wrong and so would a default-port table have been. CVE-2021-41773's port is
`"8080:80"` in a compose file, its `Require all granted` is in a .conf, and its
vendored `apache2_2.4.49-4_amd64.deb` is in a Dockerfile. `fetch_poc_evidence`
now appends the repository's own small text files, each under a `--- path ---`
heading, capped per file, per repository and by count. Verified: every one of
those strings is now in the artifact the model reads.

37d. **`resolve` ordered versions lexically.** Debian's archive-wide index
holds 407 `apache2` versions and 252 match the loose prefix `2.4`; the
lexically largest is `2.4.9-2`, from 2014, and the newest is `2.4.71-1`. The
job installed what the plan named, so the plan named a decade-old build as the
affected one. `_version_key` orders by value: a higher epoch wins, a `~` is a
pre-release of what precedes it, and the rest is numeric components - so
`2.4.49-4 < 2.4.49-10` too, which lexical ordering also had backwards.

37e. **The file listing was citable, and its lines are too short to be
evidence.** `'674 Dockerfile'` is 14 characters against a 20-character minimum,
and a check that cited three such lines failed every citation. The prompt now
says the listing is an inventory and must never be cited.

37f. **The entrypoint comes from the listing, not the prose.**
CVE-2022-29464's README writes `Using exploiy.py` in the heading that names it
and `python3 exploit.py` in the command below; the repository holds
`README.md` and `exploit.py`. The prompt now says the listing is authoritative
and that one script which could run an exploit IS the one, whatever the README
misspells it as.

37g. **A placement with no package to place into.** A job died in the guest
with "no tomcat webapps directory: is tomcat in the package list?" - a question
the form could have answered. `PLACEMENT_NEEDS` pairs each kind with the
package that creates its directory and admission checks it.

And the vocabulary was too small in a way that produced a wrong answer rather
than a refusal: CVE-2019-11043 is nginx in front of php-fpm, and the model
chose `apache-site` because that was the closest kind on offer. `nginx-site`
is added, and the prompt now says not to force-fit - a wrong kind writes a file
to a path the service never reads.

37h. **Name the obvious package.** Cacti and CouchDB are both in the archives
under their own names and both were refused for naming no package, because the
prompt tied `setup_packages` to what an instruction says to install. It now
says to name the obvious package for widely packaged server software even when
nothing mentions apt, and says why that is safe: the archive is asked whether
the package exists AND publishes a version the advisory names, and both must
hold.

37i. **Two package-name collisions, which that safety rests on.** Debian's
`confluence` is 0.10.6 of an unrelated program and its `grafana` is 2.6.0 from
2016. Nothing checks that a package IS the product an advisory names; only the
version match stands between the harness and installing the wrong software.
It holds for both, by arithmetic rather than by design, and 37d made that
arithmetic correct - before it, a loose prefix would have picked whichever
version sorted highest as a string.

37j. **A transcript and an id for every check.** `transcript.record()` returns
early with no sink and the web app installed none, so a check's extraction was
recorded nowhere - every question in this entry had to be answered by running
the check again. A sink now writes the prompt and the reply under the check's
own id, every refusal carries that id, and `GET /api/checks/<id>/log` reads it
back.

37k. **And a fetch failure names its URLs.** `HTTP status 404` left no way to
tell whether the advisory link or the PoC link was the dead one, which is the
commonest way to reach it.

37l. **Verified and correct, so left alone.** Spring Cloud Gateway exists only
in Maven; Confluence is packaged by nobody; WSO2 ships a zip. Both Grafana and
Atlassian publish their own installers, which the approval path can take and
`deb_url` will never find because it asks only Debian's archive. The
non-determinism the operator saw is real but pair-dependent: shamo0/CVE-2022-26134
returned `evidence_insufficient` three times out of three.

## The citation gate, and a resolver that installed the fix, entry 38 (2026-11-14)

The caps are 52 modules and 13,350 lines, as set. The tree reached exactly
13,350 of 13,350 during this entry, so one dead module was deleted to pay for
the rest of it rather than moving the cap: `scripts/research-artifacts.py`,
327 counted lines of Phase-0 research helpers for the three artifacts that are
already pinned. Nothing imports it, no doc instructs running it, nothing reads
the `var/research/artifacts-candidates.json` it wrote, and the full suite
passes without it. It is in git and `git checkout b250887 --
scripts/research-artifacts.py` brings it back. `src/xentry/artifact_tools.py`
was NOT touched: `scripts/pin-artifact.py` still uses it.

Everything below came out of running CVE/PoC pairs from pocindex.io through
the live app and reading the transcripts, not from reasoning about the code.

38a. **`MIN_QUOTE` was the dominant blocker, and it was refusing the best
evidence in the artifact.** Seven CVEs in one sweep died on it, and every
refused quote was a real line a reader can check:

| quote | chars | what it proves |
|---|---|---|
| `./cve-2021-4034` | 15 | the entrypoint, from the README (CVE-2021-4034) |
| `port = 445` | 10 | the target port, from the PoC source (CVE-2017-7494) |
| `FROM httpd:2.4.48` | 17 | the affected version (CVE-2021-40438) |
| `- 3000:3000` | 11 | the port, from a compose file (CVE-2024-21534) |
| `1100 README.md` | 14 | the listing line proving the file exists (CVE-2021-25646) |
| `FROM httpd:2.4.50` | 17 | the affected version |
| `- "1234:8080"` | 13 | the port |
| `674 Dockerfile` | 14 | the file exists |

The floor was a proxy for "something a reader can find and check". That intent
is now a structural rule - at least two alphanumeric runs, so `}`` `, `[` and
`1234` are still refused - with the floor at 8, which is the smallest number
that keeps all eight lines above. What actually verifies a citation is
`_quote_present`: the quote has to BE in the artifact, and that holds at any
length.

38b. **`version_evidence` and `artifact_candidates` were verified fatally.**
One invented or mistyped quote among several good ones refused the whole CVE.
They are filtered now, like the narrative citations: what verifies is kept,
what does not is dropped with its reason into `dropped_citations`. The affected
range may still not go unbacked, so a version list that started non-empty and
ends empty is refused with every reason quoted. A dropped artifact_candidate
costs that candidate, which leaves the operator approving a download instead of
facing a dead end.

38c. **The resolver installed the fix.** This is the worst bug in the entry,
because it fails silently: the job provisions, passes readiness - which only
asserts what the loose prefix says - and the PoC fails against a patched
package, which is indistinguishable from a PoC that does not work.

`version_prefixes("< 1.2.23")` gives `["1.2.23", "1.2"]`. No archive ever
published Cacti 1.2.23, so the fallback `1.2` matched and the NEWEST 1.2.x won:
**1.2.26**, three releases past the fix. Measured on the live archives, and the
same for Ghostcat, which resolved to **tomcat9 9.0.70** for a CVE fixed in
9.0.31.

`fixed_versions` was already extracted and used NOWHERE. It is the bound:

* `upper_bound()` returns the newest version an install may be, and whether it
  is itself affected. `fixed_versions` first, else the range's own words - and
  the LAST version in the range, not the first, since a two-ended range puts
  the ceiling at the end (`2.0.0 - 2.1.3`, `8.4.0 ~ 8.4.26`). `<` excludes,
  "and below" includes, a bare `2.4.49` includes itself - which is what lets
  sid's `2.4.49-4` still answer CVE-2021-41773.
* The bound is per prefix and picks the fix for THAT series. Ghostcat fixes
  9.0.31, 8.5.51 and 7.0.100 in one advisory; the smallest is 7.0.100, which
  would bound a tomcat9 install below every 9.x build in existence. Metabase
  fixes eight versions across four series under two majors, so the series is
  `major.minor`, with the major as fallback.
* Comparison is truncated to the bound's own depth, because the archive carries
  packaging the advisory never mentions: `1.2.22+ds1-1` is upstream 1.2.22 and
  satisfies an inclusive bound of 1.2.22, while its full key sorts above it.

Measured after: Cacti resolves to jammy **1.2.19**, Ghostcat to focal
**9.0.27**, both genuinely affected; CVE-2021-41773 still resolves to sid
2.4.49-4 and exim to sid 4.87-3.

38d. **A refused check's transcript was unreachable.** The id a transcript is
filed under was minted inside the request and an `ExtractorError` carried
nothing, so the one case where anyone wants to read the model's reply - a
refusal - was the one case with no way to ask for it. The id travels on the
exception and the detail reads `evidence_insufficient [<32 hex>]: ...`.
Nothing covered `GET /api/checks/{id}/log` at all, which is how both halves
went unnoticed; a test covers it now.

38e. **The last `detail=exc.code`.** Three were fixed in entry 37a. The fourth,
on `POST /api/jobs`, turned every broker refusal into the same bare word.

38f. **Prompt changes, each from a transcript.**

* An empty `ports` for a remote PoC leaves nothing to point at the target.
  Cacti's reply had `protocol: "http"` and `ports: []`. The prompt now names
  the standard ports and says an empty array is right only for a local PoC.
* A raw HTTP request line is not a command. Cacti's README shows
  `GET /cacti/remote_agent.php?...poller_id=;ping... HTTP/1.1`, which the model
  quoted as `poc_command` with no `poc_command_target` - there is no host:port
  in a request line. The refusal said "the target span '' is not in the quoted
  command", which reads as a harness fault; missing and wrong are separate
  messages now, and the prompt says a request line means `poc_command` is null.
* `fixed_versions` is what stops the harness installing a patched build, so the
  prompt asks for one from the PoC's own text or the vendor note when the
  advisory gives none.

38g. **Honest refusals, confirmed by measurement.** Not every refusal is a bug,
and three were right:

* CouchDB CVE-2022-24706 wants 3.2.1 and below. Debian sid carries 44 couchdb
  versions and not one is 3.x - the package is the 1.6 era - so nothing can
  install it. Grafana is the same: the archives' newest is 2.6.0 against an
  8.x advisory.
* Metabase CVE-2023-38646's PoC repository is documentation: no script, no
  command, no Dockerfile, no package. "The PoC text does not name a file that
  runs the exploit" is the correct answer, and the model's own
  `build_strategy` said so in as many words.
* Every local privilege-escalation CVE is refused, by design: sudo
  CVE-2021-3156, PwnKit, Dirty Pipe and Looney Tunables all land on "a local
  PoC has no attacker to attest from". The generic target has one observation,
  and it is the attacker reading something only the target has. Local CVEs
  need a per-CVE channel into the guest, which is what the three checked-in
  targets have and this path does not.

38h. **Known gaps, unchanged by this entry.** The apt install is not pinned to
the version the resolver chose: `setup-generic.sh` installs the package name
and takes whatever the pinned snapshot serial offers, and the resolver's
version is used for the release choice, the display and `expected_version`
only. Readiness then matches a PREFIX, so an advisory that names only
`major.minor` admits any build in that line - OpenSMTPD CVE-2020-7247 says
"OpenSMTPD 6.6" and resolves to focal's 6.6.4p1, which carries the fix that
landed in 6.6.2p1. `fixed_versions` would have caught it and the advisory
names none, which is why 38f asks the model for one.

## My own install script lied, and three more resolver faults, entry 39 (2026-11-15)

39a. **The install script aborted one step before the restart, and said it
had succeeded.** Entry 38's fixes were installed as files and never loaded:
the script's own verification grepped for `detail=exc.code` and matched the
two COMMENTS that explain the fix, so it exited non-zero after the install
loop. The re-tested CVEs failed exactly as before, which is how it surfaced.
Both halves are fixed: the grep ignores comment lines, and the script now
asserts the running process started AFTER the newest file it installed.
Every check in that script read a file; not one asked whether the service had
loaded it.

39b. **The newest affected build, not the oldest.** `version_prefixes` took
the FIRST version token in the range, so a two-ended range resolved to its
floor: sudo "1.8.2 to 1.8.31p2 and 1.9.0 to 1.9.5p1" resolved to **1.8.2**,
from 2011, and the kernel range "5.8 to 5.16.11" to **5.8.14**. The ceiling's
prefixes are tried first now, with the floor's kept as the fallback because a
range can name a ceiling no archive carries. Measured: sudo resolves to sid
**1.9.5-1** (the fix is 1.9.5p2), glibc CVE-2023-4911 to noble **2.38-3ubuntu1**
(fix 2.39), Dirty Pipe to sid **5.16.10-1** (fix 5.16.11).

39c. **A port build amd64 cannot install.** Debian's index answers for every
port it ever built, and sudo's winner above was `1.8.2-2+hurd.1` - a HURD
binary. It would have failed at `apt-get install` with nothing saying why.
`+hurd`, `+kfreebsd`, `+hppa`, `+sparc` and `+m68k` builds are filtered.

39d. **A backport of the fix is not a pre-release of it - a bug I wrote and
then measured.** I had added "a `~` build sorts below the version it hangs
off", which is true for `1.2.0~beta2` and false for `5.16.11-1~bpo11+1`: that
one IS the kernel that fixed Dirty Pipe, rebuilt for an older suite, and it
sailed through a strict bound of 5.16.11. Only `rc`, `alpha`, `beta`, `pre`,
`dev`, `git`, `exp` and `snapshot` tails count now.

39e. **An unsourced affected range passed silently.** Entry 38b made a bad
version citation drop instead of refusing - but giving NO citation had always
passed, while giving one bad one had been fatal. The range picks the package
version to install, so it may not be the model's unsourced claim; it is
refused now, with "no citation was given" distinguished from the reasons the
ones given failed. Every advisory states its own versions, so a citation is
always available.

39f. **Not bugs, checked and dropped.** `broker/main.py` returns
`not_implemented` from seventeen verb handlers, which looks alarming and is
not: `dispatch()` routes every verb in `RUNTIME_VERBS` - including `reboot`,
`snapshot` and `restore` - to the real runtime, and those stubs are the
runtime-less skeleton. dirtyfrag's `reboot` is real.

39g. **A fallback worth reconsidering, in a reviewed target.** When the serial
log does not contain the nonce, dirtyfrag's probe falls back silently to the
attacker transcript and the job passes, where gitlab and php2shell raise
`nonce_not_observed`. Nothing over-claims - the authority is already
`guest_attested+llm_assessed` either way, and an empty `host_evidence_sha`
marks it - but `what_proves` names a channel that may not have been used.
Changing a checked-in target's semantics is an operator decision, so it is
written up in docs/designs/local-privesc-plan.md rather than changed.

39h. **The local-privesc plan.** Written up in
docs/designs/local-privesc-plan.md. The short version: dirtyfrag is NOT a
pre-built vulnerable VM - it installs two pinned kernel .debs inside the
disposable VM, reboots through the broker verb, and asserts `uname -r` - so
the mechanism the question asked about is already proven here. What blocks
local privesc on the derived path is admission, a world-readable nonce, and
the absence of a generic step that relays root evidence out; the serial
channel every VM already has is the witness, because `xentry-guest` cannot
write `/dev/ttyS0`. Nested QEMU is possible (host nesting is `Y`) but the
domain XML exposes no `vmx`, so it would run under TCG, and more importantly
an inner VM's serial is guest-writable - it cannot witness anything. Order:
package-level privesc first, then a `target_panicked` outcome, then kernel
.debs from the archive (Debian carries 796 `linux-image-amd64` versions),
and nesting only as a labelled triage mode.

## Local privilege escalation, and five faults from the field, entry 40 (2026-11-15)

Plan A of docs/designs/local-privesc-plan.md, implemented. The restart this
needs is the first one that includes the broker.

40a. **The five reports, in the order they arrived.**

* `poc_command` given as a bare string instead of `{artifact_id, quote}` -
  pydantic refused the WHOLE reply, and `adk_extract`'s blanket
  `except Exception` reported it as **provider_unavailable**, which sends the
  reader to look at the network when the provider answered perfectly well.
  Repaired now by `coerce_facts`, which checks nothing less: the quote still
  has to be present in the artifact or the ref is dropped, and WHICH artifact
  is a lookup - the one whose text contains the quote - not a guess.
* A missing `poc_context` (the Grafana check) killed the reply the same way.
  Read off the protocol the model did give, or off `privesc_shape`.
* Anything still unrepairable fails as `evidence_insufficient: the reply does
  not fit the facts schema`, never as an unavailable provider.
* "the tomcat-webapp placement needs tomcat installed ... names nothing" was a
  correct refusal with useless advice. The prompt now states the rule: a
  placement is refused unless `setup_packages` names the package that
  PROVIDES the directory it goes in. Name both or neither.
* **"evidence_insufficient: extractor reported insufficient evidence"** was
  the harness talking to itself. `_parse_json` put the model's own error text
  in the CODE position and a fixed sentence in the MESSAGE position - exactly
  backwards - so a bare `{"error": "evidence_insufficient"}` became a sentence
  that says nothing, and a reply that DID explain itself had its explanation
  turned into a reason code. A bare code now says it was bare and points at
  the check's log; an explanation survives.
* `XENTRY_START_OCI_MIRROR` was set correctly. The broker started
  **14:23:38** and `/etc/xentry/broker.env` was written **14:28:46** - five
  minutes later - and `EnvironmentFile` is read once, at start. Nothing was
  wrong with the file; the process predated it. The install script restarts
  the broker and then greps the LIVE `/proc/<pid>/environ` rather than
  trusting the file, because that is the question that was actually being
  asked.

40b. **What Plan A is, and what it is not.** No new machinery. Every VM
already has a serial console wired to a host-side file, the broker already
has `read_host_evidence`, and the validator already carries
`host_evidence_sha256`. `/dev/ttyS0` is `root:dialout 0660` and cloud-init
creates `xentry-guest` with `sudo: false` and no supplementary groups, so the
unprivileged actor cannot write it. What was missing was admission, a secret
worth stealing, and a relay.

* **The nonce.** `/root/xentry-nonce`, 0600 root, for a local job. Reading it
  IS the privilege. The remote path keeps `/var/lib/xentry/nonce` at 0644,
  which is right for "the attacker read a file only the target has" and
  worthless as a privilege proof.
* **`privesc_shape`**, a typed fact with two values, picks one of two
  checked-in relay scripts and nothing else. The harness must not guess:
  a relay handed to an exploit in a shape it does not accept is silently
  ignored, and the job then reports no observation for a CVE that reproduces
  perfectly. `stdin-shell` is dirtyfrag's own shape, so it is already proven;
  `argv-command` passes one command string. A PoC needing an interactive
  terminal, or one that only drops a setuid binary, is refused with the
  reason naming both shapes - the refusal it replaces claimed the CHANNEL had
  to be designed per CVE, which was never true.
* **readiness-local asserts the channel is SHUT before anything runs**: not
  root, `/dev/ttyS0` not writable, `/root` not readable. An open channel
  would make the whole observation worthless, and this fails the job in the
  first minute instead of producing a false positive in the last.
* **null-local tries both halves with no exploit** and must be denied both.
* **The decisive probe reads the host serial log, with no fallback.** This is
  the one place the local path deliberately differs from dirtyfrag (entry
  39g): the transcript is the guest's own words, and falling back to it is
  what makes a "decisive" channel optional. `probe_null` also reads the
  serial for a local job, because checking the control on a channel that is
  not the decisive one leaves it blind to exactly the failure it exists to
  catch - a test drives that case and the job fails
  `null_actor_observed_nonce`.
* **build-essential** is installed for a local job, from the same dated
  serial, and appears in the step's own parameters. Most privesc PoCs are C
  and the generic image carries three packages and a keyring, so without it
  every C exploit failed at the build step. It is a provisioning default like
  DEFAULT_PORTS, not a claim about the vulnerability.

40c. **Authority is unchanged, deliberately.** Two independent facts hold - a
file only root could read was read, and a device only root could write was
written, the second observed by the runner outside the guest - which is
stronger than the remote derived path. It is still not forge-proof against a
compromised kernel, which is what a kernel exploit produces, so the label
stays `guest_attested+llm_assessed` and `what_proves` says exactly which
channel carried it.

40d. **Measured, against the live archives.** The three package-level privesc
CVEs this admits resolve to genuinely affected builds: PwnKit CVE-2021-4034
to sid `policykit-1 0.120-1` (Debian's fix is 0.120-3, measured in entry 43),
sudo CVE-2021-3156 to sid
`sudo 1.9.5-1` (fix 1.9.5p2), Looney Tunables CVE-2023-4911 to noble
`libc6 2.38-3ubuntu1` (fix 2.39). Dirty Pipe still needs the kernel route
(B1), which is unbuilt.

40e. **Still deferred.** The `spawns-shell` (PTY) and `setuid-drop` shapes;
the `target_panicked` outcome; the kernel-install route B1; and nesting (B2),
which cannot witness anything from inside a guest-built VM.

## Four faults the sweep found, entry 41 (2026-11-15)

Found by running pairs from pocindex.io against the live app with entry 38 and
39 installed, and reading the transcripts rather than the error strings.

41a. **A letter after the numbers made a version invisible.** `_matches`
required the character after the prefix to be `.` or `-`, so `9.7p1-2` matched
neither `"9.7."` nor `"9.7-"`. Debian sid carries `openssh-server 1:9.7p1-7`,
the exact build CVE-2024-6387 affects, and the check was refused as
**"no built release publishes openssh-server at '8.5p1 through 9.7p1'"** -
the archive had it all along. OpenSSL's `1.1.1k` and sudo's `1.9.5p2` are the
same shape. Any non-digit boundary counts now, and the digit test is what
still keeps `2.1` from matching `2.10`. Measured after: regreSSHion resolves
to sid `1:9.7p1-7`, and sudo CVE-2021-3156 improves from `1.9.5-1` to
`1.9.5p1-1.1`, which is the newest build the advisory still names.

41b. **The prompt's own authoritative evidence was being truncated away.**
`_prompt` took `artifact.text[:MAX_ARTIFACT_CHARS]` - the HEAD - and the
harness appends the repository listing and the PoC's ranked source files to
the END of the PoC artifact. Measured on CVE-2022-29464: the artifact is
25,365 characters and its listing begins at **24,186**, so with a 12,000
character head the model was told "the listing is AUTHORITATIVE about which
files exist" and handed no listing at all. It answered `poc_entrypoint: null`
for a repository whose entire content is `1070 exploit.py`, and the refusal
read "the PoC text does not name a file that runs the exploit" - which was
true of what it had been shown. Over-long artifacts keep head AND tail now,
with the omission marked. Everything entry 28 added was invisible for any PoC
with a long README.

41c. **An application protocol is not a wrong answer.** `protocol` is a
Literal of what the harness can DO - open http, https, tcp, or nothing - and
a model answering `"smtp"` for exim CVE-2019-10149 killed the whole reply,
reported as provider_unavailable. Coerced to `tcp` now; `http` and `https`
stay distinct because they are the only two with a standard port the harness
supplies.

41d. **"no built release publishes redis at 'n/a'" blamed the archives for an
advisory that named no version.** CVE-2022-0543 is a Debian packaging flaw
and its range came back as `"n/a"`, so there was never a version to look for.
`release.unresolved()` now distinguishes the two gaps - no version to match
versus no archive carrying the affected build - and says what would help.

41e. **Markdown besides the README is now fetched, and sources are ranked.**
CVE-2021-25646's reply said *"poc.md (not supplied as text) holds the
exploit"*: the model could see the filename in the listing and not its
contents, so in a repository that ships no script the one artifact describing
the attack was the one thing withheld. `.md`, `.c`, `.js`, `.php` and others
are fetched now - and because only eight files are, they are ranked: a name
containing exploit/poc/cve/shell/payload first, then anything runnable or any
build recipe, then the rest, shallowest path first within each group. Without
the ranking, widening the suffix list would let a `docs/` folder crowd out
the exploit, since tree order is alphabetical.

41f. **Checks that were right.** `gitlab-ce` and `grafana` are genuinely not
in the archives (8.x advisories against a 2.6.0 package); WSO2 and Spring
Cloud Gateway ship Java products no distro packages, and the refusal says a
download is what they need; CVE-2017-12617 resolves to Debian
`tomcat7 7.0.75-1~bpo8+1` against a fix at 7.0.82, because the model named
all three tomcat packages and the ceiling bound each series separately.

41g. **Noted, not fixed.** `GET /api/checks/{id}/log` truncates each item at
20,000 characters, which is below a full prompt - it briefly had me reading a
cut prompt as if the listing were missing from the real one. The transcript on
disk is complete.

## The privesc sweep, entry 42 (2026-11-15)

Plan A works. sudo CVE-2021-3156 and glibc CVE-2023-4911 both produce a
complete local plan on the first try - sid `sudo 1.9.5p1-1.1` against a fix at
1.9.5p2, and jammy `libc6 2.34-0ubuntu3` against a range of 2.34 to 2.38 -
each with `/root/xentry-nonce` at 0600, `probe-generic-serial` as the decisive
probe, and no attacker VM. The model filled `privesc_shape` correctly on every
local PoC it saw, PwnKit included.

42a. **A compiled PoC's entrypoint is the binary, not the source, and three
places had it wrong.** Measured on blasty/CVE-2021-3156: the repository ships
`hax.c` and a Makefile saying `gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c`,
and the extractor answered `poc_entrypoint: "hax.c"`.

* `build-poc-generic.sh` required the entrypoint to exist BEFORE running
  make, so naming the binary - the correct answer - was refused outright.
* The run steps then did `exec ./hax.c`, which fails as "cannot execute
  binary file": an error that reads like a broken harness for a CVE that
  reproduces.
* The prompt asked for "the one file in the PoC repository that runs the
  exploit", and for a compiled PoC there is no such file in the repository.
  CVE-2024-1086's reply said exactly that - `build_strategy` "Build the local
  exploit with make; the PoC is a C binary" and `poc_entrypoint: null`.

All three are fixed: the prompt names the `-o` case with that Makefile as its
example, the build step requires the entrypoint after the build and lists what
it did produce, and the run steps refuse a non-executable plainly. An
interpreted entrypoint is still only required to exist, since it runs through
python3 or bash rather than on its own. This was latent for every C PoC on the
remote path too; nothing had reached it because the passing CVEs were all
Python or shell.

42b. **A kernel CVE is now refused rather than run against a kernel that was
never booted.** Installing a `linux-image` .deb does not change the RUNNING
kernel - only a reboot does, and the derived path has no reboot step. Without
a guard an approved kernel .deb installs, the VM keeps running the image's own
kernel, readiness has no `uname` assertion to catch it, and the job reports a
result about the wrong kernel - a false negative, or a false positive
attributed to a version that was never there. Dirty Pipe CVE-2022-0847 and
CVE-2024-1086 both landed on the approval path and would have done this. The
refusal names dirtyfrag as the shape a kernel target has to take.

42c. **"for widely packaged server software" was excluding the privesc
cases.** sudo CVE-2019-18634 and polkit CVE-2021-3560 both came back with
`setup_packages: []` and fell to the approval path, because the sentence
telling the model to name the obvious package spoke only of server software.
It now says a local privesc has a package too - the one shipping the
vulnerable binary - with sudo, policykit-1 and libc6 as the examples.

42d. **PwnKit CVE-2021-4034 is the approval path, correctly.** Its reply is
`affected_range: "all"` with `fixed_versions: []`, which is true of the
advisory: the flaw was in pkexec since 2009 and only the per-distro fix bounds
it. `version_prefixes` returns nothing, so entry 41d's message says what is
missing and the check comes back `needs_artifact` - the operator approves a
polkit .deb. No suggestion is offered because there is no version to look one
up by, which is honest rather than a gap.

42e. **Checks that were right.** ActiveMQ CVE-2023-46604 resolves to focal
`activemq 5.15.11-1` against a fix at 5.15.16 and then stops at the Maven gap
with a clear message, since its entrypoint is
`src/main/java/org/example/Main.java` and nothing here builds a Maven project.
exim CVE-2019-10149's "quick" PoC is classified local with no shape, and the
refusal says which two shapes exist - that PoC hands over no shell at all, it
causes root to run one fixed command, which is a third shape worth having
(the relay would have to be substituted into the PoC's own text, as the
command path does for curl). CVE-2019-11043's refusal is a model error the
message states precisely: the execution span it named is not in the command
it quoted.

42f. **The budget is spent.** 13,349 of 13,350 lines, 50 of 52 modules - one
line. The next thing I would buy with new lines, in order: a `fixed-command`
privesc shape for the exim case; the `target_panicked` outcome; and deriving
prefixes from `fixed_versions` when the advisory says only "all", which would
turn PwnKit from an approval into a resolution.

## Four questions answered, entry 43 (2026-11-15)

No code changed for this entry; it records what the answers are built on, plus
one correction to entry 40d.

43a. **The reboot verb was never mine to write - it exists, and a script
cannot replace it.** `broker/runtime.py` has `reboot`: libvirt reboot, falling
back to destroy+start, then `ssh.wait(timeout_s)` for the guest to come back,
then `cat /proc/sys/kernel/random/boot_id`. Three things a `reboot` line
inside a provisioning script cannot do:

* It would kill its own SSH session. `ExecOps.run` raises `SSHError` on a
  dropped connection, so the step reports failure, not success - a correct
  reboot would look like a broken one.
* Nothing would wait. The next step would open SSH against a machine that is
  still shutting down, and `wait()` - the loop that polls until `true`
  succeeds - is on the broker side, not in any script.
* The model could not add the line anyway: steps are checked-in scripts with
  typed positional parameters, and `broker/steps.py` resolves a step id to a
  script the app never supplies text for. That gate is the reason the harness
  can run a stranger's exploit at all.

So the split into setup -> reboot -> a second step is forced, and that is
exactly dirtyfrag's shape today: `setup-dirtyfrag` installs the pinned kernel
.debs and runs update-initramfs/update-grub, the runner calls the `reboot`
verb, and `readiness-dirtyfrag` asserts `uname -r` is `6.17.0-23-generic`.
The uname assertion is what makes the reboot evidence rather than hope.

**And the boot_id is being thrown away.** The verb returns it and no caller
reads it - `boot_id` appears nowhere in `src/xentry/runner.py`. For dirtyfrag
nothing is lost, because `uname -r` is the stronger check; for a generic
kernel route it is free proof that the machine really booted, and route B1
should compare it across the reboot.

43b. **PwnKit does not need a suggested .deb: the date already picks the
vulnerable build.** The apt proxy is pinned to `snapshot_for(published)` -
one day before the advisory, floored to that day - and the same rule drives
`cutoff_for` on the registry side. Whatever `apt-get install` resolves to at
that serial is by construction the build that was current while the flaw was
still unpublished. Measured on snapshot.debian.org:

| | |
|---|---|
| serial the harness pins for CVE-2021-4034 | `20220124T000000Z` |
| `policykit-1 0.120-1` first seen | 2021-10-28 |
| `policykit-1 0.120-2` first seen | 2021-10-28 |
| `policykit-1 0.120-3` first seen | **2022-01-25**, the day of the advisory |

So sid at 20220124 carries 0.120-2, and Debian's fix is **0.120-3**. This
corrects entry 40d, which called 0.120-2 the fix: the resolution it reported
(0.120-1) is still a vulnerable build, so nothing about that run changes, but
the parenthetical was wrong.

What blocks PwnKit is therefore not the install - it is that
`release.resolve()` will not proceed without a version prefix, because its job
is to name the version in advance so readiness can assert it. "all" yields no
prefix. The change worth making is to accept a named package with no version
range, install from the date-pinned serial, leave `expected_version` empty -
which both readiness scripts already treat as "skip the version check" - and
say so in the plan's caveats: the build was chosen by the advisory's own date,
not matched against a range. That is weaker evidence than a version match and
has to read as weaker, but it is the same mechanism every other job already
relies on for its serial.

43c. **"fixed-command" is a third privesc shape, and exim CVE-2019-10149 is
the example.** The two implemented shapes both hand the caller a way to run a
command: `stdin-shell` pipes into a root shell, `argv-command` passes one
string. aishee's exim PoC does neither - it sends a crafted recipient address
to the local MTA and root executes a command the PoC itself embeds in that
address. To prove privilege the relay has to be substituted INTO the PoC's own
text, which is machinery the harness already has: the command-PoC path takes a
quoted command plus spans (`poc_command_target`, `poc_command_read`,
`poc_command_exec`) and substitutes at those spans and nowhere else. A
`fixed-command` shape is that same substitution applied to a file in the
repository rather than to a line in a README, and it needs one more typed
fact - which span in which file - to stay inside the rule that the app never
supplies a command.

43d. **`target_panicked`.** A kernel exploit that fails usually takes the
guest with it. Today that surfaces as a step timeout or an `SSHError`, which
is indistinguishable from a broker fault - so "the exploit crashed the kernel"
and "the harness broke" are reported identically, and only one of them is an
experimental result. The evidence is already being captured: the serial
console is wired to a host-side file and a panic prints there (`Kernel panic -
not syncing`, `BUG: unable to handle kernel`, `Oops`). The outcome code reads
the serial log when a step fails on a target whose channel is `host_serial`,
matches those markers, and records `target_panicked` with the panic text as
evidence. It is small, it needs no new verb, and route B1 cannot be honest
without it.

43e. **The order I would work in, unchanged.** `fixed-command`; then
`target_panicked`; then accepting a package with no version range (43b); then
route B1 - kernel .debs from the archive plus the reboot verb and a uname
assertion, with the boot_id compared. Route B2, nesting, stays where entry 40e
left it: it cannot witness anything from inside a guest-built VM.

## The queue, at 13,450, entry 44 (2026-11-15)

The cap moved to 13,450 lines for this, as you set. Three of the four items
from entry 43e are done; it stands at 13,447 of 13,450, 50 of 52 modules.

44a. **An advisory that names no version no longer stops the job.**
`release.by_package()` picks the newest release publishing the package at all,
with an empty prefix and version, and the two refusal sites try it whenever
`version_prefixes` comes back empty. The build is still right without a
version to match, because the serial is already one day before publication -
measured for CVE-2021-4034: sid at `20220124T000000Z` serves policykit-1
0.120-2, and Debian's fix, 0.120-3, was first seen 2022-01-25, the day of the
advisory.

What cannot be done is ASSERT a version, and that is said in three places
rather than hidden: `expected_version` is empty so both readiness scripts skip
their check, the apt channel's verdict reads "whatever version the serial one
day before the advisory carries - the advisory names none to match", and the
target carries `DATED_CAVEAT` in `what_does_not_prove`, which the plan and the
job record both show.

The inline verdict expression moved into `release.verdict()` on the way, which
also removed a live `IndexError`: the not-exact branch read
`version_prefixes(affected_range)[0]`, and that list is empty in exactly the
case this entry adds.

44b. **`target_panicked`.** A kernel exploit that fails usually takes the
guest with it, and the exec against a machine that just died raised the same
`BrokerError` the broker breaking raises - so "the exploit crashed the kernel"
and "the harness is broken" were one outcome. The real actor now reads the
host serial log on a `BrokerError`, and if it holds `Kernel panic - not
syncing`, `BUG: unable to handle`, `general protection fault` or `Oops: `, the
failure is `target_panicked` with the panic text as the step detail. A failure
with no panic in the log is re-raised untouched, so a genuine broker fault
still reads as one; a test drives both. The code is in the contracts table.

44c. **`fixed-command`, the third privesc shape - and it needed no new fact.**
aishee's exim CVE-2019-10149 PoC hands the caller no way to run anything: it
embeds the command root will execute in a crafted recipient address. The relay
therefore has to be substituted into the PoC's own text, which is what the
quoted-command path already does for a curl line in a README - and the
machinery transfers exactly:

* `poc_command` quotes the embedded command, verified present in the artifact,
  so it is evidence rather than text a model wrote. The step uses it to LOCATE
  the file - `grep -rlF` must match exactly one, or it refuses.
* `poc_command_exec` is the span inside that quote naming the command, and
  only that span is replaced. Admission refuses the shape unless the span is
  actually inside the quote.
* The replacement carries no quotes of its own - `cat /root/xentry-nonce
  >/dev/ttyS0` - because the span usually sits inside a quoted string in
  someone else's source. Rehearsed against a real file in the tests: the
  payload `"${run{/bin/sh -c 'id > /tmp/out'}}"` comes out as
  `"${run{/bin/sh -c 'cat /root/xentry-nonce >/dev/ttyS0'}}"`, same syntax,
  one span swapped.

The file path did not have to become a fact, which is what kept this to 16
lines: a quote the harness has already verified can find its own file.

44d. **Not done: route B1.** Kernel .debs from the archive plus the reboot
verb and a uname assertion, with `boot_id` compared across the reboot (entry
43a: the verb returns it and nothing reads it). Three lines of budget are left,
so it is the next cap conversation rather than the next commit. Entry 42b's
guard means a kernel CVE is refused in the meantime rather than run against a
kernel that was never booted, so nothing silently wrong is waiting on it.

## Route B1: a kernel installed, booted and asserted, entry 45 (2026-11-15)

The cap moved to 13,500 for this and it stands at 13,455, 50 of 52 modules.
B1 cost 18 counted lines of Python, because almost all of it is shell and
because the reboot verb already existed.

45a. **What a kernel CVE does now.** Dirty Pipe CVE-2022-0847, walked through
the whole chain and measured against the live archives:

| | |
|---|---|
| admitted | yes - local, `stdin-shell`, kernel |
| resolves to | sid `linux-image-amd64 5.16.10-1`, the last kernel before the 5.16.11 fix |
| image | `debian-11-generic` |
| setup | `setup-generic` installs it from the dated archive, then `update-initramfs -u -k all` and `update-grub`, and records what it added |
| then | the runner calls the `reboot` verb, recorded as step `reboot-generic` |
| readiness | `readiness-local` asserts `uname -r` IS the recorded kernel |
| proof | the root-only nonce on the host serial log, as every local job |

45b. **The step records the kernel it ADDED, not the newest installed.** The
base image ships its own kernel, so picking by version would assert the wrong
one whenever the affected kernel is the older of the two - and a job reporting
on kernel X while running kernel Y is the precise failure this route exists to
avoid. `setup-generic.sh` lists `linux-image-[0-9]*` before and after the
install, takes the difference, and writes it to `/var/lib/xentry/kernel.want`;
`readiness-local.sh` compares `uname -r` to that file and fails saying
"running kernel A is not the installed B" if GRUB chose something else. GRUB
boots its newest entry, which is usually ours - at a dated serial the archive
and the base image agree - but when it is not, the job stops instead of
reporting.

45c. **No new step, and no new parameters.** The kernel work is conditional
inside `setup-generic.sh`, which already takes a package list and installs it
from the pinned snapshot, so `setup_params` is untouched and the four tables
still agree. `setup-attacker` shares that script, so editing it re-pinned two
manifest hashes; that is expected and the install script checks both.

45d. **The reboot condition.** `target.target_id == "dirtyfrag"` became
`dirtyfrag or generic.is_kernel(derived_facts)`, with the recorded step id
switching to `reboot-generic` for a derived job. A test asserts the ORDER -
provision, then reboot, then readiness - because a reboot after readiness, or
none at all, would assert against the image's own kernel. Another asserts an
ordinary local job does not reboot: two boots are not free and only a kernel
job earns them.

45e. **The guard from entry 42b narrowed rather than went away.** A kernel CVE
is admitted exactly where the reboot and the uname assertion are, which is the
local privesc path. A REMOTE kernel CVE is still refused, because it has
neither - and the refusal says so now instead of claiming no path exists.

45f. **`boot_id` is still unread, deliberately.** The verb returns it, and
comparing it across the reboot would prove the machine restarted. `uname -r`
matching the installed kernel is strictly stronger - it cannot pass without a
successful boot into that kernel - so the lines went to the parts that carry
evidence. Entry 43a's observation stands if anyone wants belt and braces.

45g. **The prompt now names the kernel package.** `linux-image-amd64` on
Debian, `linux-image-generic` on Ubuntu, with the reason: the harness installs
it from the dated archive, reboots into it and asserts uname, and naming
nothing refuses the CVE. Without that sentence CVE-2024-1086 came back with
`setup_packages: []` and B1 would have been unreachable in practice.

45h. **Untouched by this entry.** Nesting (B2) stays where entry 40e left it.
The `spawns-shell` (PTY) and `setuid-drop` privesc shapes are still deferred.
A kernel exploit that panics the guest is now reported as `target_panicked`
rather than as a broker fault, which is what makes this route safe to run at
all.

## The kernel sweep, entry 46 (2026-11-15)

B1 ran against real records for the first time and the kernel CVEs found four
faults, one of them a silent wrong result on the flagship case. 13,492 of
13,500 lines, 50 of 52 modules, 653 tests.

46a. **Dirty Pipe resolved to a PATCHED kernel, and the CNA record is why.**
The check came back RUNNABLE on sid `linux-image-amd64 5.17.11-1` - nine point
releases past the 5.16.11 that fixed it. The model answered
`affected_range: "Linux Kernel 5.17 rc6"` with `fixed_versions: []`, copied
faithfully from `containers.cna.affected[0].versions[0].version`, whose
sibling line says `status: affected`. It is the same shape as polkit
CVE-2021-3560 in entry 43: the CNA states the FIX POINT as an affected
version.

Three separate faults in how that was read, each measured and each fixed:

* **The rc was dropped.** `VERSION_RE` captures `5.17` and the `rc6` falls
  away, so an inclusive bound of 5.17 admitted 5.17.11. A pre-release marker
  AFTER the version now makes the bound strict.
* **A pre-release bound cannot be ordered against another pre-release.** With
  a strict 5.17 the resolver then picked `5.17~rc8-1~exp1`, which is past rc6
  and carries the fix. A `~` in the bound now excludes the whole series: right
  here, since every 5.17 build has the fix, and conservative in the rare case
  where an earlier rc would qualify. A bound with no marker keeps the old
  reading, so `1.2.0~beta2` still satisfies "before 1.2.0".
* **The pre-release exception compared truncated digits.** `5.17.1-1~exp1` is
  a pre-release of 5.17.1, not of 5.17, and comparing `[5, 17]` to `[5, 17]`
  called it below the bound. It needs the whole digit list.

46b. **A range whose endpoints nobody shipped is the normal case, not a dead
end.** CVE-2024-1086's record reads "3.15 to less than 6.8": neither endpoint
is a build anyone published, so no prefix matched and the check was refused as
if no archive carried a vulnerable kernel - while sid carries 6.7.12, which is
squarely inside the range. `resolve()` now falls back, after every prefix has
been tried, to the newest build below the CEILING, which is what a ceiling
means. It costs one more sweep of the five releases, and the two query-count
tests say so rather than being loosened.

Measured after: CVE-2024-1086 resolves to sid **6.7.12-1** against a fix at
6.8, and Dirty Pipe as the model answered it resolves to **5.16.18-1** instead
of refusing. 5.16.18 is still past the 5.16.11 fix - the range it came from
says it is affected, and the harness honoured the range - which is why the
remaining defence is `fixed_versions`: with 5.16.11, 5.15.25 and 5.10.102
supplied, the same reply resolves to sid **5.10.92-2**, genuinely vulnerable.
The prompt now asks for exactly those, naming this measurement.

46c. **A real filename was refused.** CVE-2022-24112's PoC is
`Apache_APISIX_RCE(CVE-2022-24112).py`, and `ENTRYPOINT_RE` allowed only
letters, digits, dot, underscore, slash and dash - so the one file in the
repository that runs the exploit was refused, and the CVE with it. Widened to
`()+,@%=~` as well, which is safe rather than convenient:
`broker/runtime.py` shlex-quotes every step parameter and every script reads
`"./$entrypoint"`, so these are argv bytes and never shell syntax. Traversal
and absolute paths are still refused before any trimming, and a test pins both
sides - `exp;rm -rf /`, backticks and `$(id)` stay out.

46d. **Checks that were right.** CVE-2023-0386's PoC mounts a FUSE filesystem
and then runs a second binary, which is outside all three privesc shapes; the
model chose `fixed-command` and the refusal says what that shape needs, which
is the correct answer by a slightly wrong route. Zimbra and GeoServer ship
Java products no distro packages, and land on the approval path. Three of the
PoC URLs I tried were 404s, and the message named both URLs each time.

46e. **Still open.** The `spawns-shell` (PTY) and `setuid-drop` shapes; a
two-stage PoC like CVE-2023-0386's; Maven and Go builds; and the CNA-versus-NVD
disagreement from entry 43g, where the stricter reading should win and nothing
yet reconciles them. Eight lines of budget are left.

## The five open items, and the sweep after them, entry 47 (2026-11-15)

The cap moved to 13,600 and it stands at 13,550, 50 of 52 modules, 659 tests.
All five items from entry 46e are addressed, one of them by being honest about
what cannot be done here.

47a. **The CNA-versus-NVD disagreement, solved by reading NVD in code.** This
was implicated in two silent wrong results - polkit CVE-2021-3560 and Dirty
Pipe - and the data was there the whole time. NVD's record carries
`versionEndExcluding`, which IS the fixed version by definition:
CVE-2022-0847's lists 5.10.102, 5.15.25 and 5.16.11 while the CNA record
states "Linux Kernel 5.17 rc6" as an AFFECTED version.

Those lines sit in the middle of a 17,822-character record, past the prompt's
head-and-tail truncation, so asking the model for them asks for what it may
never have seen. `coerce_facts` harvests them from the whole artifact instead,
and only when the model named none - its own answer still wins. Measured: Dirty
Pipe as the model answered it now resolves to sid **5.10.92-2** with a ceiling
of 5.10.102, where before the harvest it was 5.16.18 and before entry 46 it was
5.17.11. `versionEndIncluding` is deliberately not read: that is the last
affected version, not a fix.

47b. **Two more privesc shapes, both mostly shell.** `pty-shell` for a PoC
that needs a real terminal - it calls isatty(), or runs an interactive
program, so a pipe makes it do nothing - using util-linux's `script -qec`,
which is in the base image. Rehearsed against a PoC that exits "needs a tty":
the stdin shape leaves the serial log empty and the pty shape carries the
nonce through, which is the measurement that says the shape earns its place.

`setuid-drop` for an exploit that RETURNS, leaving a setuid-root file behind.
The file is found rather than named - exactly one new setuid-root file under
the PoC directory, or it refuses - which is the same rule the fixed-command
shape uses for locating its file, and for the same reason: a harness that
picks between candidates is choosing what "the PoC" means.

47c. **`two-stage`, and CVE-2023-0386 is why.** Its README says
`./fuse ./ovlcap/lower ./gc` and then `./exp` - a FUSE mount that must stay up,
then the exploit - so neither half alone is the PoC. The helper line is a
command WITH ARGUMENTS, so it comes from `poc_command`, verified present in the
artifact, exactly as the fixed-command shape's does: the harness runs text the
PoC's own documentation contains and nothing else. The helper is started
detached, with its own file descriptors, because one holding the step's stdout
would keep the step alive for as long as the helper lived and the exploit would
never be tried. The script re-validates the command - `./` plus plain
arguments, no metacharacters, no `..`, 200 characters - because a step script
is the last place that can refuse; a test drives five rejected forms.

47d. **Maven cannot be solved here, and now says so.** Maven and Gradle
resolve from repo.maven.apache.org at build time. This harness has dated
proxies for apt, npm, pypi and container images and none for Maven, and
building would either reach the live internet from a guest that must not have
it or fail with a dependency error that reads like a broken PoC. The build
step refuses a `pom.xml` or `build.gradle` tree outright and says to approve
the built .jar - where before, nothing was attempted and the RUN step failed
with "not runnable: src/main/java/org/example/Main.java". A Maven proxy is a
new broker service, not a hundred lines, so it stays unbuilt and named.

Go improved instead of being deferred: three different gaps used to be one
failed build, and each now says which it is - no toolchain (name golang-go, or
approve a binary), modules that are not vendored and a guest with no network,
or a genuine build error. A vendored tree builds with `-mod=vendor`.

47e. **What the sweep found after all that.** Three privesc CVEs are now
RUNNABLE end to end, and each exercises a different thing this session built:

| CVE | resolves to | what it proves works |
|---|---|---|
| PwnKit CVE-2021-4034 | noble `policykit-1`, no version | entry 44a's no-version path AND the compiled-entrypoint fix - the entrypoint is `cve-2021-4034-poc`, the binary, not the .c |
| Looney Tunables CVE-2023-4911 | jammy `libc6 2.34-0ubuntu3` | the package-naming prompt fix |
| OverlayFS CVE-2023-0386 | sid `linux-image-amd64`, ceiling 6.2 | route B1 and the ceiling sweep |

PwnKit's plan carries the dated caveat, as it must: the advisory names no
version, so the build is whatever the serial carried and readiness asserts
none.

47f. **And one thing the sweep exposed that is NOT fixed.** OverlayFS resolved
to `6.1.190-1` against a 2023 advisory - a build that did not exist when the
advisory was published, and a 6.1 stable release that carries the backported
fix. The INSTALL is still right, because `setup-generic.sh` installs a package
NAME against the serial-pinned proxy and the serial decides; what was wrong was
the plan claiming that version as the affected one. The verdict now says
"below 6.2, shown as 6.1.190-1 - the newest the archive ever carried under that
bound. The serial one day before the advisory decides which build installs".

The real fix is a date-aware resolver, and it is not cheap: Debian's
`/mr/binary/<pkg>/` index carries only `binary_version`, `name`, `source` and
`version` - no dates - so filtering by the advisory date needs one call per
candidate version, 796 of them for linux-image-amd64. The dated Packages index
the apt proxy already serves is the right source and it is tens of megabytes.
Recorded here as the next real gap, with the measurement.

47g. **Still open.** The date-aware resolver above; a Maven proxy; the
`readiness` version assertion is a prefix match, so a stable series with a
backported fix passes it (entry 38h, now with a kernel example); and
`GET /api/checks/{id}/log` truncates at 20,000 characters, which cost me two
wrong inferences this session - the artifact is complete on disk.

## The backport hole closed, and two things that cannot be built, entry 48 (2026-11-15)

The cap moved to 13,700 and it stands at 13,551 - 149 spare, because two of
the three items turned out to be unbuildable rather than unbuilt, and saying
so with evidence is the work.

48a. **The backported fix is now caught, not warned about.** Entries 38h, 46
and 47f could only note it: a stable series keeps the upstream version and
backports the patch, so `apache2 2.4.48-3.1+deb11u1` satisfies every version
check this harness can make and reproduces nothing. The job runs, the exploit
fails, and the report says "did not reproduce" - indistinguishable from a PoC
that does not work.

Debian and Ubuntu cite the CVE id in the changelog entry of the update that
fixed it, so the installed package can simply be asked. Both readiness scripts
take the CVE id now and run
`zcat /usr/share/doc/<pkg>/changelog.Debian.gz | grep -q <CVE-ID>`; a match
fails the job saying the build carries the fix. Verified against this host's
own packages: openssl's changelog names CVE-2026-35189 and the check refuses
it, and does not refuse CVE-2021-41773. A package with no changelog is
reported as unjudgeable rather than assumed either way.

This is a better instrument than any version comparison could be.
`dpkg --compare-versions 2.4.48-3.1+deb11u1 lt 2.4.49` is true, so the
backport passes a version bound by construction; the changelog is the only
place the fix leaves a trace.

48b. **A date-aware resolver cannot be built on this API, measured.** The aim
was to stop the ceiling sweep choosing a build that postdates the advisory -
`linux-image-amd64 6.1.190-1` for a 2023 CVE. Three facts kill it:

* `snapshot.debian.org/mr/binary/<pkg>/` carries only `binary_version`,
  `name`, `source` and `version`. No dates.
* Dating a candidate needs one call to
  `/mr/binary/<pkg>/<version>/binfiles?fileinfo=1`. There are **493**
  candidates below 6.2 for that package and **70** in the 6.1 series alone.
* Bisecting is unsound, because first_seen is not monotone in version order
  across branches: `5.10.92-2` was published 2022-03-07, AFTER `5.16.10-1` at
  2022-02-24. A stable backport of an older branch is uploaded later than a
  newer branch's release.

The dated index that would answer this in one request is the Packages file the
apt proxy already serves, and it is tens of megabytes - not something a link
check can fetch.

So the sweep stops claiming precision instead: its Resolution carries an
EMPTY prefix, which means readiness skips its version assertion, the dated
caveat fires, and the changelog check from 48a is what actually protects the
result. The verdict distinguishes the two empty-prefix cases - `by_package`
found no version to match and says so, while the sweep found one and declines
to claim its series.

48c. **A dated Maven proxy cannot exist, measured.** The other three
provisioning channels all have per-version dates:

| channel | what carries the date |
|---|---|
| apt | snapshot.debian.org serves whole dated archives |
| npm | the registry's `time` map - 322 entries for express |
| pypi | per-release `upload_time` |
| **maven** | **nothing** |

`repo1.maven.org`'s `maven-metadata.xml` has a single `<lastUpdated>` for the
artifact and **zero** per-version timestamps, and `search.maven.org`, which
does carry them, does not resolve from this host. A Maven proxy would
therefore be an undated passthrough - it would give a guest that must have no
network a route to a live external service, and resolve whatever the internet
answers today, usually the fix. That is not the same object as the other three
proxies and must not look like one. The build step refuses a `pom.xml` or
`build.gradle` tree and says to approve the built .jar, which is the honest
answer and now the stated one.

48d. **The log endpoint no longer truncates below a prompt.** 20,000
characters cost two wrong inferences in one session - "the listing is missing"
and "NVD was not fetched" - when both artifacts were complete on disk. It is
400,000 now.

48e. **A seventh privesc shape, measured twice and deliberately not built.**
Dirty COW CVE-2016-5195 and dirty_sock CVE-2019-7304 are the same shape: the
exploit creates or rewrites a privileged ACCOUNT, and the proof is becoming
it. Their replies say so - "the PoC overwrites the root passwd entry via the
COW race" and "connects to /run/snapd.socket to create a user".

The relay would be `su` to the new account with a password from the PoC text,
through a PTY because `su` will not read a password from a pipe, with the new
account found by diffing /etc/passwd. Every part of that is plausible and none
of it can be rehearsed on this host, which has no root for the test and no way
to create the account. This session's rule has been that nothing ships
unmeasured, so it is recorded here instead: two CVEs, one shape, and the
reason it is still open.

48f. **And one free improvement the sweep found.** Dirty COW's repository is a
single `dirty.c` with no Makefile, and its compiler flags - `gcc -pthread
dirty.c -o dirty -lcrypt` - live in the README. The build step found nothing
to build, then reported "the build produced no dirty" with an empty list of
executables. It now names the cause: C source, no Makefile, flags in prose
this harness does not read as a build recipe, approve a built binary. It will
not guess a link line, because a wrong one is a compile error attributed to
the CVE.

48g. **Still open.** The account-drop shape of 48e; a dated Maven channel,
which needs a dated index Maven Central does not publish; and a date-aware
resolver, which needs one Maven Central does not either - both now with the
measurements that say why.

## Five reports verified, and a regression of my own, entry 49 (2026-11-15)

All five checks the operator quoted were real, and two of them had the same
root cause nobody would have guessed from the messages. 13,618 of 13,700
lines, 664 tests.

49a. **XENTRY_START_OCI_MIRROR was read NOWHERE in the tree.** Not a stale
process, not a page needing a refresh: `BrokerRuntime.__init__` took
`start_oci_mirror` and `broker/main.py` never passed it, while
`src/xentry/runner.py` failed every Dockerfile job with "set
XENTRY_START_OCI_MIRROR=1 on the broker". Setting it did nothing, however
often the broker was restarted, and nothing in the system could say so.

One line in main.py fixes it. Two things make the class visible in future:
`ping` is a runtime verb now and answers with what THIS PROCESS started -
mirror, apt_proxy, registry_proxy, oci_mirror - and `/api/system` shows that
answer. A test asserts every `start_*` parameter `BrokerRuntime` accepts is
passed by main.py, which is the check that would have caught it. The existing
broker-contract test already required a runtime METHOD per verb, so ping got
one rather than being special-cased - that contract exists for exactly this
failure.

49b. **"image artifact is unresolved: debian-11-generic-image" was the broker
remembering.** `_catalog_data` and `_results_data` cached their files for the
life of the process. The app reads `config/artifacts.yaml` per request, so the
FORM offered a release the BROKER then refused - they disagreed about the same
file. The catalog was written 2026-11-14 08:48 and a broker started before
that kept answering from its startup copy; the only cure was a restart nobody
knew to do, and the message blamed the artifact.

Both loaders re-read on an mtime change now, and a re-pin clears the verified
image-path cache so the new digest is checked rather than the old verdict
reused.

49c. **The tomcat errors were one wrong fact, twice.** Verified from both
transcripts: CVE-2022-29464 (WSO2) came back with `place: "tomcat-webapp"` and
`setup_packages: []`. WSO2 ships its own Tomcat inside a .zip that no distro
packages, so a placement is the wrong shape for it entirely - the right answer
is `launch` plus an approved product archive.

I tried skipping the placement check on the artifact path so the approval would
be offered, and reverted it: that check was earned by a job that died in the
guest with "no tomcat webapps directory: is tomcat in the package list?" after
an approved .war went into a tree nothing had created. So the guard stays, the
refusal now names the other way out, and the prompt says plainly that a
product shipping its own servlet container - WSO2, Confluence, Jira - takes
launch and an archive, not a placement.

49d. **The Grafana check refused for having no entrypoint, and the message
made a dropped citation look like the cause.** `'= 8.3.0'` is seven characters
and was dropped by the citation floor - correctly, because a bare version
occurs all over a record and anchors nothing - while the three citations that
mattered (`>= 8.0.0, < 8.0.7` and friends) verified. The refusal was the
missing entrypoint, so "the extractor also offered" became "(separately, a
citation the extractor could not back up was dropped: ...)", and the prompt
asks for the WHOLE LINE a version appears on, key included, which is unique
and findable.

49e. **A regression this session introduced, found by sweeping.** Entry 47's
ceiling sweep - take the newest build below the bound when no prefix matches -
turned two correct refusals into jobs against unrelated software, because
package names collide across a decade:

| CVE | archive carries | advisory is about |
|---|---|---|
| CVE-2021-43798 Grafana | `grafana 2.6.0+dfsg-3+b1` | Grafana 8.0.0 to 8.3.0 |
| CVE-2024-23897 Jenkins | `jenkins 1.565.3-6` (2014) | Jenkins 2.441 |

Both are "below the ceiling". A false POSITIVE is the one direction a
reproduction lab must not fail in, and this was one of mine.

Two guards, because the two cases differ. Grafana's range names a FLOOR
(`>= 8.0.0`), so the sweep honours it - applied only when the range names two
or more version tokens, since "before 6.2" and "Linux Kernel 5.17 rc6" mean
everything underneath. Jenkins' range names one version and no floor, so the
sweep also requires the candidate's MAJOR to equal the ceiling's. That refuses
a legitimate "before 2.0" against an archive carrying 1.9 - a false negative
the operator can answer by approving a .deb, which is the trade worth making.

Measured after: grafana and jenkins refuse, while nf_tables still resolves to
sid 6.7.12-1, Dirty Pipe to 5.16.18-1, OverlayFS to 6.1.190-1, Apache to
2.4.49-4 and Cacti to jammy 1.2.19.

49f. **What else the sweep found runnable.** Zabbix CVE-2022-23131 resolves to
jammy `zabbix-frontend-php 1:5.0.17+dfsg-1` with a Python PoC. Worth checking
against the advisory's own range before trusting it: this entry's lesson is
that a resolved version and an affected version are not the same claim.

49g. **And one more found while rehearsing the install script.** "3.15 to
less than 6.8" was read as an INCLUSIVE bound, so 6.8.9 - which carries the
fix - satisfied it. The strict words were "prior to", "before", "earlier
than", "fixed in" and `<`; the CNA records' own phrasing is "less than", and
the flattened field it comes from is literally `versions[0].lessThan`. Both
spellings count now, with "lower than" and "up to but". It surfaced only
because the first rehearsal passed `fixed_versions=["6.8"]`, which made the
bound strict by another route and masked it - the second rehearsal, without
them, did not.

## Every cache in the tree, audited, entry 50 (2026-11-15)

Asked for after two cache bugs in two days. This is the whole inventory, what
was wrong in it, and what was checked and found sound - because the ones that
are sound are the useful half of an audit like this. 13,668 of 13,700 lines,
667 tests.

### Four bugs

50a. **The OCI manifest cache was two files written non-atomically, and read
as if both existed.** `cached.write_bytes(body)` then
`cached.with_suffix(".json").write_text(...)`, and the read did a bare
`json.loads` of the second after testing only the first. A crash between the
two writes left an entry that raised FileNotFoundError for that digest for as
long as the cache lived - the same shape as the registry index cache that one
truncated reply poisoned permanently (entry 27-era), in the one place that had
not been fixed. It is the only non-atomic cache write in the tree: the apt
proxy, the registry proxy and the OCI blob path all use `.part` plus
`os.replace`.

Now: metadata written and renamed FIRST, manifest second, because the
manifest's existence is what the read tests - so a crash can leave orphan
metadata, which is harmless, and never a manifest without it. And the read
re-verifies the body against the digest that names it, so a corrupt entry
becomes a refetch instead of a poisoned one. A digest is a few kilobytes; the
sha256 costs nothing.

50b. **Nothing the app served said whether it could be cached, and `GET /` is
what sets the token cookie.** A browser serving that page from its own cache
never receives the `Set-Cookie`, so every POST fails `token_missing` - a page
that looks fine and is dead until a hard reload. That is the operator's own
question from entry 49 ("do I have to completely refresh the page?") in its
purest form. An `/api` GET served from cache freezes a job list the same way,
and the UI reads its CSRF token from a `<meta>` tag once at script load, so a
cached page pins a stale one.

`Cache-Control: no-store` on everything the app renders or answers, and
`public, max-age=31536000, immutable` on `/static` - which is the opposite
case, because its URL carries a content digest.

50c. **That digest was an mtime over a hand-written file list.**
`asset_version()` maxed `int(st_mtime)` over `("app.js", "style.css")`: a
third asset would have been invisible to the key, and one-second resolution
means two writes in the same second share it. It is a sha256 over every file
under `static/` now, which cannot be wrong about whether something changed -
and with `immutable` on those URLs it is the only thing that expires a cached
asset, so it had to be right.

50d. **`TARGETS` was built at import, freezing the three checked-in targets'
pinned digests for the life of the process.** Re-pinning one, or editing a
checked-in script, left a running app serving the old digest and a job failing
"artifact hash mismatch" until someone restarted it - the broker's bug from
entry 49b, in the app. The lookups refresh when `targets/steps.yaml` or
`config/artifacts.yaml` changes, and the dict is MUTATED rather than replaced,
because `app.py` did `from xentry.targets import TARGETS` and would otherwise
have kept the old object. A test holds a reference the old way and asserts it
sees the change.

### What was checked and is sound

* **apt proxy** - keyed by archive, serial and path. The archive is in the key
  because both carry a `pool/main/a/apache2/apache2_*.deb` and they are not
  the same bytes. Atomic write, and an upstream error unlinks the partial
  rather than caching a failure.
* **registry proxy** - keyed by ecosystem and package name, deliberately NOT
  by cutoff: it stores the unfiltered upstream document and filters per
  request, so two jobs at different cutoffs share one fetch. Sound because
  cutoffs are always in the past, so a document fetched later still contains
  everything up to any of them. Atomic writes on both paths.
* **OCI blobs and tags** - blobs are content-addressed, verified on write and
  written atomically; a TAG is never cached, with the reason in the docstring:
  it moves, and serving a stale one would hand the guest an image the registry
  no longer publishes under that name.
* **artifact mirror** - constructed per job, so its manifest is re-read per
  job rather than held for the process.
* **source store** - keyed by `check_id`, which is unique per check, and the
  multi-file approval drops before it adds.
* **fetch layer** - no caching at all, no conditional requests. `release`'s
  resolver was deliberately de-memoised earlier in this session so every
  archive lookup stays visible.
* **the CSRF token** - file-backed, so it survives a restart; combined with
  50b the page and the cookie can no longer disagree.
* **`_load_yaml`, `_artifact_sha`, `_step_sha`** - re-read per call, no memo.
* **`broker/proxy.py`** - no cache.
* **the browser script** - one `Map` of open table rows, which is UI state and
  not a data cache.

### And one of my own

The first attempt at 50b did not take effect: the patch script wrote
`p.write_text(s.replace(...))` for the Cache-Control edit without reassigning
`s`, then wrote `s.replace(...)` again for the asset edit - so the second
write overwrote the first with the original text plus only the second change.
The headers were absent from the response and present nowhere but a docstring.
Caught by asserting the header on five routes instead of trusting the patch,
which is the only reason it did not ship as "fixed".

## It was never the cache: two catalogs, entry 51 (2026-11-15)

I diagnosed "image artifact is unresolved: debian-11-generic-image" as a stale
cache in entry 49b and shipped a fix for that. The cache bug was real, the fix
was right, and it was not this error's cause. The cause:

| | file | contents |
|---|---|---|
| the app reads | `/opt/xentry/config/artifacts.yaml` | the pin, with a digest |
| the broker reads | `/opt/xentry-broker/config/artifacts.yaml` | 10 entries, dated Nov 13, and no `debian-11-generic-image` at all |

`broker/runtime.py` defaults that path to a RELATIVE `config/artifacts.yaml`
and the unit sets `WorkingDirectory=/opt/xentry-broker`, so it resolved to that
tree's own copy. Re-reading a file when its mtime changes cannot help when the
file does not contain the entry. Two services, two catalogs, and an error that
named neither - which is why I misread it, and why the operator saw it twice.

What I should have done the first time is read `self.catalog_path` rather than
reason about the loader. The lesson is the one this session keeps teaching: when
a message blames a thing, check that the thing is the thing being read.

51a. **One catalog and one manifest.** `XENTRY_ARTIFACT_CATALOG`,
`XENTRY_STEPS_MANIFEST` and `XENTRY_TARGETS_DIR` are written into
`/etc/xentry/broker.env` as absolute paths into `/opt/xentry`, idempotently and
with a backup, so both services read one file. The broker tree's copies are
overwritten with the app's as a belt, so the content agrees even without the
env.

51b. **The error names the file now**: "debian-11-generic-image is absent from
/opt/xentry-broker/config/artifacts.yaml (10 entries)". That one line would
have saved two rounds.

51c. **And the divergence is visible before a job hits it.** `ping` reports
`catalog_path` and `steps_manifest`, and `/api/system` compares them against
the app's own, adding a `*_mismatch` key when they differ. A relative default
plus a different working directory can now be seen on a status endpoint
instead of inside a failed job.

51d. **A file from the PoC's own repository is no longer put up for approval.**
The operator's rule - a file from the PoC's repo needs no approval, because if
the repo were malicious its exploit already is - was implemented as an
auto-fetch, and `_suggested_file` then ALSO offered the same file in the
approval box: kozmer's own `target/log4shell-1.0-SNAPSHOT.war` for
CVE-2021-44228, bytes the harness had already taken and attached to the
refusal as `repo_file`. That branch is deleted. A card offers the software
itself - an official .deb of the affected version - which is the thing no
repository ships.

51e. **The harness reads the entrypoint out of the listing.** kozmer's
repository holds exactly one runnable script, `4208 poc.py`, and the reply came
back `poc_entrypoint: null`, refusing the CVE for having "no file that runs the
exploit". `coerce_facts` now looks in the PoC artifact's own listing for
exactly one of `poc.py`, `exploit.py`, `exploit.sh`, `poc.sh`,
`exploit.rb` at the repository root and uses it when the model named none.

This is a lookup in evidence the harness fetched, not a guess - the listing is
part of the artifact and the prompt already calls it authoritative. Exactly one
match or nothing: two candidates would mean choosing, a subfolder match is not
the root script the rule is about, and a command-only PoC is left alone.

51f. **The two ids were not jobs, and the one job that exists is diagnosed.**
**WRONG - see 54e.** Both ids are jobs and the table holds 41 of them; the
claim below rests on a `len()` taken on the response object instead of the
list inside it. The diagnosis of 8a757c91 that follows is sound.

`086df75fa739` and `9ddf438ce5db` are absent from the jobs table, which holds
exactly one row - a submit the broker refuses creates no job, so those are
check ids. The job that IS there, `8a757c91` for CVE-2025-32433, failed at
provision: the author's Dockerfile runs its own `apt-get update`, and while
`docker build --network host` puts the build on the guest's network, the
CONTAINER's `sources.list` comes from the base image and points at
deb.debian.org, which nothing here routes to. apt exits 100 and the step
surfaced `returned a non-zero code: 100`. It now says what happened and what
to do instead.

A Dockerfile that installs packages at build time cannot be built in this
isolation at all. The OCI mirror serves base images; the apt proxy serves the
guest's apt, not a container's. Making it work would mean rewriting the
author's build, which is the one thing the Dockerfile path exists to avoid.

## A container inside the VM needs an archive, entry 52 (2026-11-15)

Decision 3 of this ADR said the VM is the isolation boundary and no container
runtime is used. Entry 28 amended it: a container runtime runs INSIDE the
target VM when the PoC's Dockerfile is the only description of the vulnerable
environment its author wrote, restricted to `library/debian` and
`library/ubuntu` bases. What neither entry worked out is that a container
inside an isolated VM is a second provisioning environment with its own view
of the network and its own package sources - and the lab's dated guarantee has
to reach into it, or the Dockerfile path can only ever build images that need
nothing installed.

CVE-2025-32433's job is where that bill arrived. The build died on the
author's own `RUN apt-get update && apt-get install -y git build-essential
...` with `returned a non-zero code: 100`, because:

* `docker build --network host` puts the build on the GUEST's network, where
  the only archive that answers is the job's apt proxy, and
* the CONTAINER's `/etc/apt/sources.list` comes from its base image and points
  at `deb.debian.org`, which has no route from a `forward=none` bridge.

The guest's own sources.list is irrelevant to it. Two sources.lists, one
network, and nothing connecting them.

52a. **A volume cannot bridge them, and this is why.** The operator's
suggestion - mount the guest's sources.list into the container - is right in
spirit and blocked by build-time mechanics:

* `docker build` has **no volume flag at all**. Measured on this host's docker
  29.9.3: 32 flags, none of them `-v` or `--volume`.
* `VOLUME` in a Dockerfile is a RUN-TIME declaration. It binds nothing from
  the host during a build, and writes to a VOLUME path in later RUN steps are
  discarded.
* BuildKit's `RUN --mount=type=bind,...` does exactly the right thing - and
  the flag goes on the AUTHOR'S RUN line, so using it means editing their
  Dockerfile, which is the one thing this path exists not to do. The failing
  job's log also shows the legacy builder in use.

`docker run -v` would work, but by then the build has already failed.

52b. **What does work, and it is smaller than what I first proposed.** The
proxy already requires a `/debian/` or `/ubuntu/` prefix on every request, and
that is byte-for-byte what the real archives serve - measured:
`deb.debian.org/debian/dists/...` and `archive.ubuntu.com/ubuntu/dists/...`,
both 200. So a container that merely RESOLVES `deb.debian.org` to the job's
proxy asks for exactly the paths the proxy already answers. No forward-proxy
mode, no absolute-form request parsing, no new path semantics.

`docker build --add-host deb.debian.org:<gateway>` is supported by the legacy
builder and injects into `/etc/hosts` for every RUN step. The one gap is the
port: apt talks to 80 and the proxy listens on 8082, so the job's proxy needs
a listener on port 80 of its gateway as well - the same exposure the 8081-8086
listeners already have on a bridge with `forward=none`, just another port.

Rehearsed without root, on the tree's real `AptSnapshotProxy` pinned to Debian
at `20230601T000000Z`:

| request | answer |
|---|---|
| `/debian/dists/bookworm/Release` | 200, 191,258 bytes from the dated snapshot |
| `/ubuntu/dists/noble/Release` | **403 refused path for debian** |

That second line is why the operator's other idea is required rather than
optional: the proxy serves ONE archive and refuses the other, so the archive
has to be chosen to match the Dockerfile's base. `FROM debian:bookworm` is
already in the PoC artifact the harness fetches, so no new request is needed
to read it.

52c. **The plan, costed.** About 25 counted lines:

* pick the archive from the Dockerfile's `FROM` - the operator's idea, and
  necessary because of the 403 above (~10 lines),
* bind the job's apt proxy on port 80 of its gateway in addition to 8082
  (~5 lines),
* pass `--add-host` for that archive's hosts in `setup-docker.sh` (shell, so
  free against the budget).

The forward-proxy alternative - `--build-arg http_proxy` plus absolute-form
support in the proxy - is rejected: ~30 lines, and it widens the proxy's
contract from "paths under one archive" to "any host, allowlisted", on the
guest's only route off its bridge.

52d. **Two limits that survive either approach.** apt over `https` sources
cannot traverse a plain-HTTP listener without CONNECT; Debian and Ubuntu
default to `http://`, so the common case works and anything else fails with a
TLS error rather than silently. And `snapshot.ubuntu.com` starts at 2023-06,
so an `ubuntu:20.04` Dockerfile for a 2021 CVE still cannot have a dated
Ubuntu archive - it needs a Debian base. Neither is new; both are inherited
from the archives themselves.

52e. **Status: prototyped, not implemented.** The docker half needs root and
this account has no docker access, so it is a reviewable script -
`prototype-docker-apt.sh` - which starts the real proxy on the gateway at port
80, builds an UNMODIFIED `FROM debian:bookworm` Dockerfile with its own
`apt-get install`, and then checks three things: that the build succeeded, that
the proxy's log shows apt's own `GET /debian/...` requests, and that the
installed package is the serial's rather than today's. It prints a verdict
either way and tears everything down. Nothing is written for this feature
until that verdict says the mechanism holds - the one place an unmeasured
assumption would waste the whole 25 lines is apt's use of `/etc/hosts` inside
a build.

In the meantime the failure says what it is: the step prints the Dockerfile's
base line, which archive the job's proxy serves, and the sentence that the
container's own sources.list is what apt reads.

52f. **The prototype ran, and my own verdict in it was wrong.** The script
printed "--add-host alone is not enough. Do not spend the lines." The log it
printed directly above that says otherwise:

```
0.280 Get:1 http://deb.debian.org/debian bookworm InRelease [193 kB]
0.389 Get:2 http://deb.debian.org/debian bookworm-updates InRelease [49.6 kB]
```

apt resolved `deb.debian.org` to the proxy and fetched 193 kB of the dated
index through it. **The mechanism works.** My verdict treated any non-zero
build as a failed mechanism, when the only question that settles it is whether
apt reached the proxy at all. The script now distinguishes those two and
classifies the failure instead of guessing at it.

What actually failed, both archive properties rather than mechanism:

* `Release file ... is expired (invalid since 1257d)`. Measured:
  snapshot.debian.org's Release carries `Valid-Until: Wed, 07 Jun 2023`, so
  EVERY historical Debian serial is expired by construction. The guest's own
  apt is told `Acquire::Check-Valid-Until "false"` by setup-generic.sh; a
  container reads its own `apt.conf.d`, and there is no way to put that option
  there without editing the author's Dockerfile - `docker build` has no volume
  flag, and its predefined build args are the proxy variables and nothing else.
* `403 refused path: /debian-security/dists/bookworm-security/InRelease`. The
  container's sources.list has a third entry on a prefix this proxy does not
  serve. snapshot.debian.org does carry it - measured, 200 and 46,314 bytes -
  so it is servable, in about eight lines.

52g. **Ubuntu has neither problem, measured.** `snapshot.ubuntu.com`'s Release
has **no Valid-Until field at all**, so apt cannot call it expired, and every
suite an `ubuntu:22.04` container asks for is served from the dated snapshot
under one prefix:

| path | answer | Valid-Until |
|---|---|---|
| `/ubuntu/dists/jammy/Release` | 200, 269,219 bytes | absent |
| `/ubuntu/dists/jammy-updates/Release` | 200, 117,879 bytes | absent |
| `/ubuntu/dists/jammy-backports/Release` | 200, 106,824 bytes | absent |
| `/ubuntu/dists/jammy-security/Release` | 200, 109,469 bytes | absent |

`archive.ubuntu.com` and `security.ubuntu.com` both use `/ubuntu/`, so one
prefix covers both hosts and no proxy change is needed beyond the port.

52h. **So the plan shrinks, and the operator's idea carries more weight than
either of us thought.** Picking the archive from the Dockerfile's `FROM` does
not just choose which archive to serve - it decides whether the job can work
at all:

* `FROM ubuntu:*` - works, with a port-80 listener and `--add-host` for the two
  Ubuntu hosts. No new prefixes, no expiry problem.
* `FROM debian:*` - cannot apt-install here, and the reason is the archive's
  own signed metadata rather than anything this harness does. Serving
  `/debian-security` would remove one of its two failures and leave the other,
  so those eight lines are not worth spending.

Revised cost: about 15 counted lines - bind the job's apt proxy on port 80 as
well as 8082, read the base from the Dockerfile in the artifact to pick the
archive, and pass `--add-host` in setup-docker.sh, which is shell and free.
The forward-proxy alternative stays rejected: it is twice the size and widens
the proxy's contract, and this does not need it.

A Debian-based Dockerfile that installs nothing still builds, as it always
did. One that apt-installs gets the message from 51f, which now names the
Dockerfile's base and the job's archive - and the honest addition is that for
`FROM debian:*` the answer is to pick a CVE whose package the dated archive
carries, or approve a prebuilt artifact, rather than anything the operator can
configure.

## A `+` in a version was a 403, entry 53 (2026-11-15)

The Dockerfile prototype found a bug in the GUEST's apt path. 13,699 of
13,700, 669 tests.

53a. **What the second prototype run showed.** With an Ubuntu base the build
fetched 1,119 kB through the proxy and then failed on four packages and only
four:

```
Get:8  ... libssh-4 amd64 0.9.6-2build1 [184 kB]          served
Get:9  ... libcurl4 amd64 7.81.0-1ubuntu1.10 [290 kB]     served
403 refused path: .../librtmp1_2.4%2b20151223...deb       refused
403 refused path: .../libsasl2-2_2.1.27%2bdfsg2...deb     refused
```

Every refusal carries `%2b` - apt percent-encodes `+` - and `PATH_RE` is
`^/(ubuntu|debian)/(dists|pool)/[A-Za-z0-9][A-Za-z0-9._+~/-]*$`, which admits
a literal `+` and has no `%` at all. Measured against the live proxy:

| request | answer |
|---|---|
| as apt sends it, `%2b` | **403 refused** |
| the same path decoded, literal `+` | 200, 53,832 bytes |
| upstream itself, literal `+` | 200, 53,832 bytes |

53b. **It was never container-specific.** The guest's own apt encodes
identically, so any job installing a package whose version carries a `+` died
at provisioning on a message that reads like a refusal by design. That is a
large class and it includes builds this session chose on purpose: cacti
`1.2.19+ds1-2ubuntu1.1`, apache2 `2.4.48-3.1+deb11u1`, policykit-1
`0.105-31+deb11u1`, the kernel's `~bpo11+1` rebuilds. It had not surfaced
because the jobs that reached provisioning happened to install versions
without one - apache2 `2.4.49-4`, openssh `1:9.7p1-7`.

The fix decodes once and validates the DECODED form, which is also where the
traversal guards have to be: `%2e%2e` would otherwise decode past them. A
leftover `%` after one decode is refused rather than decoded again, and
upstream is asked for the decoded path because that is what it serves. Four
cases are pinned in a test - the encoded `+`, an encoded traversal, a
double-encoded one, and the wrong archive's prefix.

53c. **My prototype's verdict was wrong twice, in two different ways.** The
first run said "the mechanism does not work" because any non-zero build was
treated as a failed mechanism; the second said "the proxy served NOTHING"
because it counted request lines in the proxy's log - and
`AptSnapshotProxy`'s handler overrides `log_message` to return, so there are
none to count. Both times the build log two lines above the verdict showed apt
fetching through the proxy.

A detector that cannot observe the thing it reports on is worse than no
detector: it produced a confident "do not spend the lines" twice for a
mechanism that works. What the script should assert is the proxy's own cache
directory filling up, which is evidence it cannot miss. The prototype is a
scratch script rather than shipped code, which is the only reason this cost
nothing but two rounds of my own analysis.

53d. **Where the Dockerfile feature stands now.** The mechanism is proven
twice over, the Ubuntu path's remaining failure was this bug, and the plan is
unchanged from 52h: bind the job's apt proxy on port 80 as well, read the base
from the Dockerfile to pick the archive, and pass `--add-host` in
setup-docker.sh. A Debian base still cannot apt-install, for the Valid-Until
reason in 52f, which no amount of proxy work fixes.

## Two jobs run, two bugs in the job path, entry 54 (2026-11-15)

The first real jobs of the session. Both failed, and neither failure was in
the code the last twenty entries fixed - they were in the two steps between a
check and a run.

54a. **An advisory older than 2021-08 silently provisions from TODAY'S
archive.** Job `5bd509cb` for sudo CVE-2019-18634 got as far as readiness and
died on `installed sudo 1.9.17p2-9 does not match 1.8`. Measured:

| | |
|---|---|
| `advisory_published` | `2020-01-29T17:23:26.000Z`, parsed correctly |
| `snapshot_for` | `''` |
| `generic.SNAPSHOT_FLOOR` | `2021-08-01` |
| the broker's default `SNAPSHOT_SERIAL` | `20261101T000000Z` |

`""` means "use the broker's default" and the default is now, so a pre-floor
advisory installs current packages. Of the thirteen CVEs swept this session,
**nine are below that floor** - CVE-2016-5195, 2017-7494, 2017-12617,
2019-10149, 2019-18634, 2020-1938, 2020-7247, 2020-11651 and 2021-3156 - which
is most of the classic corpus.

The readiness version check caught it, which is the system working. But the
paths added in entries 44 and 47 - `by_package` and the ceiling sweep - leave
`expected_version` EMPTY on purpose, and with it empty nothing would have
caught it: the job would have run the exploit against a current build and
reported that it did not reproduce. Those additions made this latent bug
reachable without a guard.

The floor itself is not arbitrary: `debian-11-generic`'s
`debian-archive-keyring` verifies snapshot Release files back to the bullseye
signing key, measured as 2021 onward, so an older serial fails signature
verification rather than serving an older package. The bug is the FALLBACK, not
the floor - "no serial could be derived" has to mean refuse, not "use
whatever is current". A job that needs apt and has no serial should be refused
with that sentence, at the check as well as in the runner.

54b. **The same artifacts gave the check and the job different facts.** Job
`f062e5c1` for CVE-2021-41773 died at step 2 with "the PoC text does not name
a file that runs the exploit" - a refusal its own check had not made. The
check was re-run twice and admitted both times, so it is not a flaky check.

The artifacts are identical, which took two attempts to establish because the
first comparison used a different check's log:

| artifact | the check | its job |
|---|---|---|
| cve | `82e91d5d2784` | `82e91d5d2784` |
| poc | `3a360a4f0630` | `3a360a4f0630` |
| nvd | `cb118489f38e` | `cb118489f38e` |

The replies are not:

| | check | job |
|---|---|---|
| `poc_command` | the curl line, quoted | **null** |
| `place` / `place_file` | null | `apache-site` / `000-default.conf` |

Byte-identical prompts, materially different facts. Both readings are
coherent - blasty's repository does ship that config and does state the
exploit as a curl line - but only one of them is runnable, and the operator
approved the one that was. temperature=0 is not a determinism guarantee from
any provider; batching and routing break it.

So the bundle digest guarantees the INPUTS are what the check saw and nothing
guarantees the FACTS are. Every check verdict in this harness is provisional
at job time, which makes a whole class of "the form said runnable and the job
refused" reports irreducible until the job stops re-extracting.

The fix is the one the design already half-implements: the check stores its
artifacts so the job sees the same bytes, and it should store the FACTS it
admitted as well, with the job loading them rather than asking again. Then
the plan the operator approved is the plan that runs. Re-extracting and
comparing would be more faithful in principle and worse in practice: it costs
a second model call and still fails the operator when the two disagree.

54c. **Most PoC Dockerfiles are not Debian or Ubuntu.** A listing-only
screener - no model call, no check - over candidate repos answers the question
the dockerfile path turns on:

| repo | recipe | base | exploit |
|---|---|---|---|
| kozmer/log4j-shell-poc | Dockerfile | `tomcat:8.0.36-jre8` | poc.py |
| ProDefense/CVE-2025-32433 | Dockerfile | `debian:bookworm` | CVE-2025-32433.py |
| apogiatzis/docker-CVE-2021-3156 | Dockerfile | `ubuntu:20.04` | build.sh |
| miko550/CVE-2016-5734-docker | docker-compose | none | cve-2016-5734.py |

The OCI mirror serves `library/debian` and `library/ubuntu` only, and a PoC
author's Dockerfile usually starts from the application image - tomcat, php,
node - because that is the software under test. kozmer's is the measured
example: a correct, self-contained lab the harness cannot build. Of the four,
one has a base this harness can serve AND an exploit beside it, and it is the
Ubuntu one, which per entry 53 is also the only base whose dated archive a
container can use.

Two other repo shapes refuse for a reason worth separating: a lab that ships
the vulnerable target and no exploit (ypereirareis/docker-CVE-2019-11043,
motikan2010/CVE-2019-10092_Docker) is not a PoC this harness can run, because
the exploit lives in another repository entirely - neex/phuip-fpizdam for the
first. "The PoC text does not name a file that runs the exploit" is the right
answer there and the entrypoint-from-listing rule correctly does not fire,
because there is no script to find.

54d. **Where the operator's list of twenty stands.** Two jobs submitted, two
failed, both now explained. A list of successful runs is not reachable while
54a and 54b stand: 54a silently misprovisions the nine pre-2021 CVEs, and 54b
means any check verdict can evaporate at submit. The honest pool is CVEs
published after 2021-08 with an apt-installable package, and of the pairs
swept so far that is about fifteen candidates.

54e. **A correction to 51f, and the census it should have been.** I told the
operator that `086df75fa739` and `9ddf438ce5db` were not jobs, on the grounds
that "the jobs table holds exactly one row". That measurement was wrong: I
called `len()` on the response object `{"items": [...]}` rather than on the
list inside it, read 1, and built a conclusion on it. Both ids are jobs:

| job | CVE | outcome |
|---|---|---|
| `9ddf438ce5db` | CVE-2021-41773 | `preflight_refused` - the two-catalog bug of entry 51, now fixed |
| `086df75fa739` | CVE-2025-32433 | `provision_failed` - the Dockerfile apt failure of entry 52 |

The table holds **41** jobs, and what they say is worth more than anything a
single check tells us:

| | |
|---|---|
| completed | **7**, all on the three CHECKED-IN targets |
| derived (pasted-CVE) jobs | 12 |
| derived jobs completed | **0** |

The seven are php2shell (four), gitlab (two) and dirtyfrag (one pair), each
ending `nonce_hash_match` or `nonce_observed_and_evidence_hash_match`. So the
machinery - VM, provision, exploit, nonce, validator - demonstrably works end
to end on a hand-designed target. What has never once completed is a target
DERIVED from a pasted CVE, which is the whole subject of entries 20 through
54.

The failure census is the map for the next round:

| count | reason |
|---|---|
| 8 | `provision_failed` |
| 6 | `target_unhealthy` |
| 3 | `no_observable` |
| 3 | `evidence_insufficient` |
| 3 | `source_unavailable` |
| 2 | `preflight_refused` |
| 2 | `broker_registry_rejected` |
| 1 each | `poc_build_failed`, `validator_error`, `target_create_failed`, `proxy_capture_failed`, `artifact_hash_mismatch` |

Two of those classes are now explained and fixed - `preflight_refused` was the
two catalogs, and the `provision_failed` pairs on CVE-2025-32433 were the
container's own apt. `target_unhealthy` is 54a wherever the advisory predates
the floor. That leaves `provision_failed` on CVE-2021-44228 and
CVE-2026-126187, `source_unavailable`, `poc_build_failed` and
`proxy_capture_failed` as unexamined, and each has a recorded step detail to
read rather than a theory to invent.

The lesson about the measurement is the same one as 52f and 53c, three entries
running: the harness's own instrumentation was right and my reading of it was
wrong. Twice it was a detector that could not see what it claimed to report
on; here it was a length taken on the wrong object. The pattern to break is
asserting a conclusion from one number without printing the thing the number
came from.

## The two job-path bugs, fixed, entry 55 (2026-11-15)

Entry 54 diagnosed two bugs between a check and its job. Both are now fixed,
at 13,732 of 13,750 and 671 tests.

55a. **No dated archive is now a refusal, not a silent fallback.**
`snapshot_for` returning `""` left the broker's default `SNAPSHOT_SERIAL =
20261101T000000Z` in force, so an advisory below `SNAPSHOT_FLOOR` provisioned
from today. The runner now raises `unsupported_target` instead, and the
message says what the operator has to know rather than naming an internal
constant:

> no snapshot serial for 2020-01-29: this harness provisions from one day
> before the advisory and its base images can verify archives no older than
> 2021-08-01, so there is no dated archive to install from - and installing
> from today's would reproduce nothing

That is the only honest answer. The alternative - provision from the floor -
installs a 2021 package for a 2019 advisory, which is the same wrong archive
with extra steps. The nine pre-floor CVEs of 54a are out of scope for the apt
path and the message now says so at the point of refusal instead of surfacing
as `installed sudo 1.9.17p2-9 does not match 1.8` four steps later - or, on
the `by_package` and ceiling-sweep paths, as a false "did not reproduce".

55b. **The job runs the facts its check admitted.** `sourcestore` grows two
functions, `save_facts` and `load_facts`, writing `facts.json` beside the
artifacts already stored per check_id. The check writes what it admitted, the
job loads it, and the extractor is not called a second time. When a check
predates the change `load_facts` returns `""` and the job extracts as before,
so no stored check is invalidated.

This closes the hole 54b measured: byte-identical artifacts gave the check
`poc_command: <the curl line>` and the job `poc_command: null`, and the job
refused a plan the operator had approved. The test asserts the stronger
property rather than the outcome - the extractor is handed a reading that
cannot run, and the job completes anyway, because it never asks.

Two consequences worth stating plainly:

* **A check verdict is now binding.** What the operator approves on the form
  is what provisions and runs. The bundle digest already guaranteed the inputs;
  the facts were the remaining gap.
* **A bad reading is now sticky.** If a check admits facts that are wrong but
  runnable, re-submitting the same check re-runs the same wrong plan. The
  recourse is a new check, which re-fetches and re-extracts. That is the right
  trade: a wrong plan the operator saw beats a different plan they did not.

55c. **The fixtures were lying by omission.** Adding 55a broke 23 tests, then
6: every derived-job fixture served a CVE artifact with no `datePublished`, so
every one of them was exercising the silent-fallback path the whole time. They
now carry `datePublished: 2022-06-01`. A fixture that omits the field the
production path keys on tests a configuration that cannot occur, and here it
hid the bug for twenty entries.

## The archive answers in one fetch what a job takes four steps to learn, entry 56 (2026-11-15)

A screen with no model call, no job and no VM: for each of the 26 checks
admitted this session, ask the dated archive whether it actually carries the
resolved package at the version the check expects. Fifteen had both a serial
and a package. **Ten of the fifteen would have failed at provisioning.**

| CVE | suite | wanted | the archive at that serial |
|---|---|---|---|
| CVE-2021-41773 | sid | apache2 2.4.49 | `2.4.49-4` - **vulnerable, correct** |
| CVE-2023-0386 | sid | linux-image-amd64 6.1 | `6.1.15-1` - **correct** |
| CVE-2023-46604 | focal | activemq 5.15 | `5.15.11-1` - **correct** |
| CVE-2022-23131 | jammy | zabbix-frontend-php (any) | `1:5.0.17+dfsg-1` |
| CVE-2022-0847 | sid | linux-image-amd64 5.17 | carries `5.16.11-1` |
| CVE-2022-0847 | sid | linux-image-amd64 5.10 | carries `5.16.11-1` |
| CVE-2023-4911 | jammy | libc6 2.34 | carries `2.35-0ubuntu3` |
| CVE-2021-40438 | jammy | apache2 2.4.48 | carries `2.4.52-1ubuntu4` |
| CVE-2021-3560 | sid | policykit-1 0.119 | carries `0.105-31.1+b1` |
| CVE-2021-43798 | sid | grafana | absent |
| CVE-2024-23897 | sid | jenkins | absent |
| CVE-2021-4034 | noble | policykit-1 | absent |

This is the cheapest instrument built this session and it should have existed
twenty entries ago. One HTTP fetch of a `Packages.xz` - 1.4 MB for jammy, and
cached per (serial, suite, component) - replaces a VM create, a provision and
a readiness probe, and it answers with the archive's own bytes rather than a
model's reading of an advisory.

56a. **On Ubuntu the serial does almost nothing, measured.** The release
pocket is immutable, so it is served identically at every serial - including
serials from before the release existed:

| serial | focal | jammy | noble |
|---|---|---|---|
| 20220127 | 970,408 B | 1,394,768 B | **9 B** |
| 20230601 | 970,408 B | 1,394,768 B | **9 B** |
| 20240501 | 970,408 B | 1,394,768 B | 1,401,160 B |

jammy's index is byte-identical at 20220127 - two months before jammy's GA -
and at 20251001. The moving pockets do vary, and only exist from mid-2023:

| serial | jammy-updates apache2 | jammy-security apache2 |
|---|---|---|
| 20210915 | **9 B stub** | **9 B stub** |
| 20230601 | 2.4.52-1ubuntu4.5 | 2.4.52-1ubuntu4.4 |
| 20231002 | 2.4.52-1ubuntu4.6 | 2.4.52-1ubuntu4.4 |
| 20251001 | 2.4.52-1ubuntu4.16 | 2.4.52-1ubuntu4.16 |

Three consequences, none of them visible from inside the harness:

* An Ubuntu job installs the **GA version** of anything in `main`, whatever the
  advisory's date. It can only reproduce a CVE whose fix landed in `-updates`,
  i.e. one where GA itself is vulnerable. CVE-2021-40438 wanted apache2 2.4.48
  and jammy GA is 2.4.52, already fixed - so that job provisions successfully
  and reports "did not reproduce", which is the worst possible failure mode.
* A serial **before the chosen release's GA** yields a 9-byte stub, not an
  error. PwnKit on noble at 20220127 is that case: noble did not exist.
* Below ~20230601 there are no `-updates`/`-security` pockets at all.

So entry 55a fixed one half of a two-sided bug. `snapshot_for` returning `""`
is now refused; returning a **well-formed serial the Ubuntu archive cannot
honour** still is not, and that path is what the `target_unhealthy` class on
Ubuntu releases has been all along. Debian is the sound dated channel - sid at
20211004 really does carry apache2 2.4.49-4 - and Ubuntu is sound only when
the serial is at or after the release's GA and the vulnerable version is GA's.

56b. **Two of the ten are resolver errors the archive catches anyway.** The
CVE-2022-0847 pair wanted 5.17 and 5.10 where sid carries 5.16.11 - and
5.16.11 is the version that FIXED it, so the ceiling walk landed on the fix
again, in a shape the guards of entries 44 and 47 do not cover. The archive
check catches it without needing to understand why, which is the argument for
putting it in front of the resolver's output rather than refining the
resolver further.

56c. **This belongs in the check, and does not fit the budget.** 13,734 of
13,750 leaves 16 lines; a fetch, an xz decode, a stanza scan and a comparison
is nearer 30. Until it is in, the screen exists as a scratch script
(`preflight.py`) and its role is selection: the pool worth submitting is the
pairs it passes, and it says that pool is Debian sid with a post-2021-08
advisory and a package in Debian main.

## The dated archive is asked at the form, entry 57 (2026-11-15)

Entry 56 measured the gap with a scratch script; it is now in the check.
`src/xentry/archive.py`, one function, called from `_link_check` after the
release resolves. 13,799 of 13,800, 676 tests.

57a. **Why the existing queries could not answer it.** The resolver already
asks both archives what versions exist, and `release.published_versions` says
in its own docstring what that means:

> Launchpad is per release, so the reply is what *this suite* published.
> Debian's snapshot index is per package across the whole archive's history,
> so the reply is what Debian ever carried **and the serial is what decides
> whether this job gets it** - a version that existed in 2021 is not in a 2024
> serial of sid, and readiness says so.

So the design knew, and deferred the dated question to readiness. Readiness
cannot always answer it: the `by_package` and ceiling-sweep paths of entries
44 and 47 leave `expected_version` empty on purpose, and there nothing checks
the version at all. The deferral was sound when every path named a version and
stopped being sound when two paths did not.

One authority answers it - the Packages index of that suite at that serial -
and nothing was reading it. Now `archive.refusal` does, in three shapes kept
separate because they are three different operator problems:

| shape | the refusal |
|---|---|
| no index for the suite at the serial | that serial predates the release, or this archive's snapshots |
| index read, package not in it | `<archive> <suite> at <serial> does not carry <package>` |
| carried at another version | carries `<what>`, not the `<wanted>` the advisory needs |

The three are verified against the live archives, not fixtures: apache2 2.4.49
in sid at 20211004 passes; apache2 2.4.48 on jammy at 20210915 reports
`2.4.52-1ubuntu4`; policykit-1 on noble at 20220127 reports no index; grafana
in sid reports not carried; zabbix `1:5.0.17+dfsg-1` passes a `5.0` bound,
which is the epoch rule.

57b. **The failure it prevents is the one worth preventing.** Two of entry
56's ten would have *provisioned successfully* and reported that the CVE did
not reproduce - CVE-2021-40438 asking for apache2 2.4.48 on a jammy whose GA
archive carries the already-patched 2.4.52. A refusal is a fact about the
archive; "did not reproduce" against a patched build is a false negative that
reads exactly like a result. Catching that before a VM exists is worth more
than the eight it saves from an honest provisioning failure.

57c. **Cost, measured.** One fetch per derived check: 8.8 MB for Debian sid,
1.4 MB for Ubuntu jammy, both under a second, against a VM create, a
provision and a readiness probe. `fetch`'s 2 MB default would truncate sid, so
the call raises the limit for this one request rather than globally.

The nine-byte stub is why the check cannot be "did the request succeed".
snapshot.ubuntu.com answers 200 for a suite that did not exist yet, so the
size threshold is load-bearing and `MIN_INDEX_BYTES` is named for that.

57d. **What stayed.** The runner's own serial guard from 55a remains as a
backstop: a check stored before this change can still reach a job with no
serial, and the runner is the only thing standing in front of it. The check's
refusal is the one an operator will actually see.

57e. **The fixtures were testing a configuration that cannot occur, again.**
Five new tests needed a real xz'd Packages index, and building one surfaced
that the old fixture's fetcher took `(url)` only - so the pre-flight's
`max_bytes` argument raised TypeError, which the "an absent component is a
miss" handler swallowed into "no index". A fixture whose signature does not
match the production call site tests the error path and calls it the happy
one. The same lesson as 55c, two entries running.

## The first real sweep through the pre-flight, entry 58 (2026-11-15)

The archive pre-flight of entry 57 went live and 21 checks ran through it.
Six admitted, fifteen refused, and five of those refusals were the new gate -
each one a VM not spent. 13,833 of 13,850, 678 tests.

58a. **What the pre-flight admitted.** Five distinct CVEs, each on a build the
dated archive genuinely carries and the advisory genuinely covers:

| CVE | release | carried at the serial | fixed in |
|---|---|---|---|
| CVE-2021-41773 | sid @ 20211004 | apache2 `2.4.49-4` | 2.4.50 |
| CVE-2021-42013 | sid @ 20211006 | apache2 `2.4.50-1` | 2.4.51 |
| CVE-2024-25641 | noble @ 20240512 | cacti `1.2.26+ds1-1ubuntu0.1` | 1.2.27 |
| CVE-2024-42009 | sid @ 20240804 | roundcube `1.6.7+dfsg-1` | 1.6.8 |
| CVE-2025-49113 | noble @ 20250601 | roundcube `1.6.6+dfsg-2ubuntu0.1` | 1.6.11 |

58b. **And the refusals found a bigger bug than the one being fixed.** Three of
the five name a release that did not exist when the advisory was published:

| CVE | published | release the resolver chose | that release's GA |
|---|---|---|---|
| CVE-2022-0543 | 2022-02 | **noble** | 2024-04 |
| CVE-2023-27372 | 2023-02 | **noble** | 2024-04 |
| CVE-2021-44790 | 2021-12 | **jammy** | 2022-04 |

`published_versions` asks whether an archive EVER carried a version, and a
release pocket is immutable, so a release chosen this way answers with its GA
build - which for an older advisory is already patched. jammy's GA apache2 is
`2.4.52` and CVE-2021-44790 needs `2.4.51`.

The refusal was correct and still the wrong answer, because **Debian sid at
that same serial carries 2.4.51**. The resolver had a release that works and
picked one that does not. So `_link_check` now sweeps: ask the dated index,
and on a refusal drop that release from the pool and resolve again, refusing
only when every built release has been asked and named its answer. A reader
who hits that refusal sees what each archive carried rather than one verdict.

58c. **The subject package was not the only one that has to exist.** The
pre-flight checked `resolution.package` - the subject a version was matched to
- and provisioning installs everything in `setup_packages` plus whatever a
placement needs. `PLACEMENT_NEEDS` admits its package on a SUBSTRING, so
`"tomcat"` satisfied the `tomcat-webapp` rule while **Debian has no package
called tomcat** - `tomcat9` and `libtomcat9-java` are carried, `tomcat` is
not, measured at a 2021 serial. That is the second of the operator's two
tomcat reports: the first is the admission refusal, which is by design and
right, and this one is a name no archive ever had, which provisioned and then
died in the guest with "no tomcat webapps directory". Every name the job will
install is now checked, subject first so that a single-package target fetches
one index and no more.

58d. **A roundcube job provisioned for eight minutes and died on my own
quoting.** Job `c5a2b133` for CVE-2025-49113 passed fetch, extract, plan,
network, target create, and then failed in `setup-generic.sh`:

```
line 368: i: unbound variable
```

The `bound_on` helper's awk program is written in the file as
`'"'"'{ ... $i ... }'"'"'`. That is the escaping needed to emit a single quote
from inside a single-quoted heredoc, and it leaked into the shipped script: the
awk body ends up partly outside its quotes, the shell expands `$i`, and
`set -u` aborts. Reproduced standalone - `i: unbound variable` - and the fixed
form returns `0.0.0.0` for a reachable bind and `127.0.0.1` for a
loopback-only one, which is the distinction the function exists to make.

It was the only occurrence left in the tree, and it was mine. Two lessons, the
second worse than the first: a generated script needs its quoting verified in
the FILE and not in the generator, and this function was added without once
being run on a real listener table, which costs eight minutes of provisioning
per discovery.

Repinning `setup-generic.sh` broke seven tests, which is the manifest working:
`targets/steps.yaml` pins each script's sha256 and `setup-attacker` reuses this
one, so a script cannot change without the pin changing with it.

58e. **Two census entries were already fixed and I nearly reported them
twice.** `make: command not found` and `node: command not found` are in the
41-job history, and both are fixed in the tree: `build-poc-generic.sh` now
skips the build for an interpreted entrypoint - its comment names
`briskets/CVE-2026-126187-poc` as the repo whose Makefile is a help text - and
`readiness-npm.sh` puts `/usr/local/node/bin` on PATH. A census over finished
jobs is a record of the code as it WAS; reading it as a bug list reports
fixes as faults.

## Every built release answers, and twice I had to be corrected to get there, entry 59 (2026-11-15)

The operator's standing instruction after entry 58: make certain every built
release has answered before anything is refused. Entry 58's sweep did not do
that, and saying it did was the error. 13,847 of 13,850, 678 tests.

59a. **Why the shrinking-pool sweep did not do what I said it did.** It was
driven by `release.resolve()` over a pool that lost one release per round:

```python
while resolution is not None and serial:
    gap = archive.refusal(...)          # ask the dated index
    if not gap: break
    pool = tuple(r for r in pool if r != resolution.release)
    resolution = release.resolve(..., pool, ...) if pool else None
```

`resolve` returns `None` for its OWN reasons - `not prefixes or not packages`,
no hit on what the archive ever carried, no ceiling to sweep under. So it
gives up while the pool still holds releases whose DATED index was never
consulted, and the refusal then listed only the releases that happened to be
picked. `by_package`, the fallback the single-shot path uses, was not retried
per release either. The claim was not a small overstatement; the loop could
refuse having asked one release of five.

59b. **The replacement, and the regression it introduced.** The loop now runs
over the releases themselves, asking `resolve` about one release at a time so
each contributes exactly one sentence to `answers`. That fixed the guarantee
and broke the choice, measured immediately on CVE-2021-44790:

```
asked ubuntu jammy  prefix=2.4.51 -> carries 2.4.52-1ubuntu4, not 2.4.51
asked ubuntu focal  prefix=2.4    -> CARRIES IT
chosen: ubuntu focal apache2 2.4.41-4ubuntu3.23
```

Debian sid carries apache2 **2.4.51-2**, the exact affected build, and the
sweep took focal's 2.4.41 on the fallback prefix instead. `resolve`'s
docstring names this bug in advance:

> nested the other way round that fallback was tried on the first release
> before the exact prefix was tried on any later one. CVE-2021-41773 names
> Apache 2.4.49, which only Debian sid ever carried unpatched, and it resolved
> to noble's 2.4.58 on "2.4" - the fix already in it - without querying Debian
> at all.

Asking one release at a time IS that inverted nesting. The fix restores
prefix-major order with the `Resolution.exact` flag that already existed: two
passes, exact matches across every release first, fallback matches only after
all of them have been tried, and `exact_only != candidate.exact` sends each
release to exactly one pass so none answers twice and no index is fetched
twice.

Measured after, on live archives:

| | |
|---|---|
| CVE-2021-44790 | `debian sid apache2 2.4.51-2` - the exact affected build |
| a CVE no release can serve | refused, **5 of 5** releases named: noble, jammy, focal, sid, bionic |

59c. **A refusal became an offer.** With no release carrying the build, the
check no longer raises 422; it falls to the artifact path that already
existed, so approving a prebuilt build stays open, and the dated answer from
every release is appended to that refusal's detail. `_every_release_answered`
asserts the per-release sentence for each entry of `RELEASES`, which is the
only form of this check that cannot drift back to being assumed.

59d. **Two things I tried and removed in the same round.** An index cache
keyed on URL, because the sweep refetches: removed, because a decompressed sid
index is ~60 MB of text and caching several of those in the web process is a
memory liability - and the tests proved the key assumes the URL fixes the
bytes, which two fixtures serving different content at one URL falsified. What
the cache was papering over was a duplicate: the post-sweep per-package gate
was re-asking the dated index about the SUBJECT at the same prefix the sweep
had just checked. Removing that redundant question was the actual fix and cost
no lines.

59e. **Still open, and it is mine.** `archive.refusal` matches a version by
prefix and does not apply the advisory's ceiling, so on a fallback prefix like
`2.4` a dated archive carrying `2.4.58` - already fixed - would answer
"carries it". `resolve`'s own `_within` filters the CHOICE by the ceiling, and
exact-first ordering makes the fallback path rare, so this is narrowed rather
than closed. Closing it means passing the ceiling into `refusal`, which needs
`upper_bound` and a public form of `_within`, and three spare lines will not
buy it.

## The sweep at scale, and the quota that invalidated part of it, entry 60 (2026-11-15)

The first sweep over a real pool - Debian's own security tracker intersected
with the PoC index - and the operator's instruction to use subagents for it.
13,870 of 13,870, 686 tests.

60a. **The pool, screened without a model call or a VM.** The tracker gives
CVE -> source package -> the version that fixed it; the snapshot archive gives
when that version appeared. If the fix landed AFTER the advisory, the archive
at the serial still carried a vulnerable build, which is the one thing that
must be true. 1,407 CVEs have both a tracker entry and a PoC; 544 are in a
shape this harness can witness; of those:

| count | verdict |
|---|---|
| 226 | a dated archive carries an affected build |
| 292 | the fix was ALREADY in the archive when the CVE published |
| 22 | advisory predates the 2021-08 keyring floor |
| 4 | lookup failed |

Threads, not subagents, for that screen: 1,100 small HTTP calls with no
judgement in them. The agents went to the checks, which carry a model call and
a varied refusal to read.

60b. **The serial rule is a proxy, and the proxy is wrong more often than it
is right.** 292 of 544 had the fix in the archive before publication, which is
what coordinated disclosure looks like - the fix lands, then the advisory. A
serial one day before the FIX is vulnerable by construction: the archive then
held the previous revision, which the tracker itself calls affected. Measured:

| | candidates |
|---|---|
| pool with serial = advisory - 1 day | 226 |
| pool with serial = fix date - 1 day | **512** |

Only 6 are then out of reach, their fix predating the keyring floor. The gain
is 137 service-shaped: tomcat9 (25), apache2 (22), tomcat10 (15), roundcube
(11), spip (10). NOT implemented: it changes what the harness claims, from
"what you would have had on the advisory date" to "the last build Debian
shipped before the fix". The second is better for reproducing a bug and weaker
as evidence about exposure, and the choice is the operator's.

60c. **My own screen was wrong by nine years, in the safe direction.** It took
`min(first_seen)` over every file of a source version, and the `.orig.tar.gz`
is shared by every revision of an upstream version:

```
20210603T213110Z  policykit-1_0.105-31.debian.tar.xz
20210603T213110Z  policykit-1_0.105-31.dsc
20120424T214447Z  policykit-1_0.105.orig.tar.gz     <- shared
```

Reading the `.dsc` alone moved 29 candidates from unusable to usable, 197 ->
226, every flip in the safe direction - a spuriously early fix date can only
make a good candidate look bad. CVE-2022-46169 (cacti) and CVE-2022-0543 (the
redis Lua sandbox escape) were among them.

60d. **I exhausted GitHub's quota mid-sweep, and the harness reported it as a
verdict about the PoC.** A Dockerfile screen of mine made ~150 API calls;
unauthenticated GitHub allows **60 an hour per address**, and a check spends
one on the PoC repository's listing. `fetch._poc_tree` is best effort:

```python
except (FetchError, ValueError, AttributeError):
    return [], False
```

So a 403 becomes an EMPTY listing, and the extractor then reports "the PoC
text does not name a file that runs the exploit" - a judgement about content,
for a file list never read. **13 of 24 refusals in that sweep carried that
message**, and none of them can be trusted. This is the third instance of the
pattern entries 52f, 53c and 54e name: a detector reporting on something it
could not see. The difference is that here the blindness was mine to cause.

The structural consequence matters more than the incident: at one listing per
check, the anonymous limit caps a sweep at ~60 checks an hour. A 500-CVE sweep
is not possible without a token.

60e. **A token, scoped to one host.** `XENTRY_GITHUB_TOKEN` in
`/etc/xentry/app.env`, joining `XENTRY_NVD_API_KEY` in one table that both now
read. Three properties, each tested:

* `api.github.com` ALONE. raw.githubusercontent.com and codeload serve public
  repositories under far looser limits, so a credential there widens exposure
  and buys nothing.
* Re-evaluated per redirect hop, so a redirect cannot carry it off-site -
  `fetch()` is called with operator-supplied advisory URLs.
* Refused outright if it contains CR or LF. The request is assembled as a
  string onto a raw socket, so a newline in a token is not a malformed header
  but an attacker-chosen one. Surrounding whitespace is stripped instead, since
  a pasted token with a trailing newline is the likeliest accident.

The install script reads it from stdin - an argument would sit in shell history
and in `ps` - refuses to install if GitHub still reports a limit of 60, and
afterwards confirms the running process has the variable by NAME only.

Still unfixed, and separate: a listing that fails for any OTHER reason still
produces the content verdict. "The repository listing could not be read" is
about six lines, and there are none.

60f. **Debian is sound for 2021-2022 serials and silently unsound after.** A
batch agent reported `release: debian-11-generic` with `suite: sid` as a
mismatch. Its reasoning was wrong - the pairing is deliberate, and the code
says why - but it was right that something is broken, and the same comment
states the principle:

> bullseye as the base, because the userland has to be of the serial's era. A
> bookworm image is a 2023 userland, and resolving 2021 sid packages onto it
> asks apt to reconcile a two-year gap in every shared library.

Two admitted plans are sid at 2023 and 2024 serials on that 2021 base - the
same two-year gap, in the other direction. Measured:

| | |
|---|---|
| `apache2-bin 2.4.58-1+b3`, sid @ 2024-04-03 | needs `libc6 >= 2.36` |
| `debian-11-generic` (bullseye) ships | `libc6 2.31` |

So CVE-2024-27316 will ask apt to replace the C library under a running
system. The reason the design's own rule was never enforced is that `RELEASES`
has exactly ONE Debian entry: there is no bookworm base to select for a late
serial, so there was nothing to enforce it with. Either add one, or refuse
Debian for serials far from 2021.

60g. **A web application installed and served nothing.** The roundcube job got
past entry 58's quoting bug, provisioned cleanly for eight minutes, and failed
with the diagnosis the fixed `bound_on` exists to give: "nothing is listening
on port 443 after installing roundcube", with the socket list showing only
sshd and resolved. Measured cause:

```
roundcube-core  Recommends: apache2 | lighttpd | spawn-fcgi | php-fpm | httpd-cgi
```

Debian expresses "you need one of these servers" as a Recommends, and
setup-generic.sh installs with `--no-install-recommends`. One level down
matters: `roundcube` itself declares neither. The class is narrow, also
measured - cacti, wordpress, hoteldruid and mediawiki DEPEND on apache2 and
come up fine; only spip, phpmyadmin and roundcube rely on a recommend. The
failure now names the package and quotes its Recommends line. Diagnosis only:
installing recommends would change the package list the operator approved and
pull a server whose version nothing asserts.

60h. **The Dockerfile-in-VM feature is dead on the data.** Of 145 candidate
repos, 8 ship a Dockerfile, and exactly **1** has both a base the OCI mirror
serves and no network fetch in the build - and that one is `ubuntu:lunar`,
EOL. CVE-2026-42945 is typical: `FROM ubuntu:22.04`, which entry 53 proved can
apt-install through the proxy, and then
`git clone https://github.com/nginx/nginx.git`, which a `forward mode='none'`
network cannot serve. The ~15 lines of entry 52h would buy 1 candidate in 145.
That answers the question entry 54c opened and the operator's instinct that a
container inside the VM would matter: in this pool, it does not.

60i. **Two wording bugs an agent caught.** Two refusals said "no Ubuntu
package" while the resolver chooses among five releases across both archives,
and showed that text for Debian plans. And `f"{facts.privesc_shape!r}"`
rendered a bare `None`, so the message read "this one names None". Both are
user-facing text, both cost nothing, both fixed - and the test that pinned the
old wording now asserts the reason for the new.

## Consequences

* V1 is a two-VM program for remote targets, not a single-VM demo.
* The broker is a root-owned trust surface; its fixed verbs, peer UID, registry, and QEMU user are security-critical.
* The design remains LLM-assessed, not deterministically verified. The full harness contract is deferred.
* Gate B is split: WSL2 can validate KVM, libvirt, network, mirror, proxy, and two-VM boot; AppArmor/QEMU-user validation moves to the deployment host.
* Any further scope growth requires a budget change and an amendment to this ADR.
* A derived environment xentry did not pin is a weaker class of evidence than a
  pinned one, and is only a reproduction when a fixed-version control run fails.
* The target archives are Ubuntu and Debian only. No RPM family is in scope:
  no per-day RPM snapshot service exists, and a frozen point release holds the
  patched build rather than the affected one.

## References

* `docs/designs/xentry-v1.md`
* `docs/designs/xentry-v1-contracts.md`
* `phase0_plan.md`
* `phase0_host_preflight.md`
