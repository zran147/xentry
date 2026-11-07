# Target setup scripts

Checked-in, hand-reviewed, hash-pinned setup scripts for the three V1 targets.

Rules:

* `provision_user` is `root`; the broker allowlists each `setup-*` step id.
* The actor is `xentry-guest`; it has no sudo, setuid, pkexec, or writable root-owned path.
* The setup script receives `mirror_url` as a typed step parameter. It must not embed a job-varying address.
* No `apt-get update` against the internet; packages are baked into the images and target artifacts come from the mirror.
* The script hash is recorded in `config/artifacts.yaml` and verified before execution.
* No LLM authoring or repair in V1. Generated provisioning is V1.1.
