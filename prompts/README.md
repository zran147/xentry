# Prompts

Phase 0 skeleton. The extractor prompt is added in Phase 0/1; the validator prompt is added with the app in Phase 1.

Rules:

* The extractor has no tools and returns typed `Facts` with citations.
* The validator has no tools, no generator history, and receives labeled runner facts plus untrusted narrative.
* Prompts are versioned and hashed; a prompt change invalidates the fixture gate.
