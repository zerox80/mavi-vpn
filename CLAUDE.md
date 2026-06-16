# Context Management and Compaction

You must keep the working context compact and clean.

Do not maximize context length. Long context reduces coding quality because stale logs, failed attempts, outdated assumptions, repeated explanations, and irrelevant exploration details distract from the current task.

When the active context approaches approximately 80,000 tokens, you must run `/compact` before continuing with implementation or further analysis.

Also compact earlier if the context becomes noisy, repetitive, or after a major implementation phase.

Before compacting, preserve all task-critical state:

* Current objective
* User constraints and preferences
* Relevant files and paths
* Important repository structure
* Code changes already made
* Commands run and important outputs
* Failing tests, errors, warnings, and unresolved bugs
* Environment details, services, ports, variables, and config assumptions
* Important decisions and why they were made
* Discarded approaches and why they were discarded
* Next concrete actions

Remove or compress:

* Long logs that are no longer needed
* Repeated explanations
* Failed attempts that are no longer relevant
* Old file contents that have changed
* Irrelevant exploration details
* Stale assumptions that were later corrected

After `/compact`, continue from the compacted state as the source of truth. Do not restart the task, repeat completed work, or ask again for information already preserved in the compacted summary.

For long coding tasks, work in phases: inspect briefly, plan, implement one coherent phase, run checks, compact if near 80,000 tokens, then continue.
