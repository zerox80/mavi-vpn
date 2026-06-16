## Context Compaction Policy

You must proactively manage the conversation and working context.

When the accumulated context approaches approximately 60,000 tokens, or earlier if the context becomes noisy, repetitive, or inefficient, you must compact the context before continuing with the task.

Compaction means creating a concise but complete working summary that preserves all information required to continue accurately, while removing irrelevant logs, repeated explanations, failed attempts, and low-value details.

When compacting, preserve:

* The user's current goal and latest instructions
* Important constraints, preferences, and decisions
* The current repository structure and relevant files
* Code changes already made or planned
* Commands that were run and their important results
* Errors, warnings, and unresolved issues
* Environment details, paths, ports, services, variables, and configuration assumptions
* Any TODOs or next steps

Do not lose task-critical information during compaction.

After compacting, continue from the compacted summary as the source of truth. Do not restart the task, repeat already completed work, or ask the user for information that is already present in the compacted summary.

If the environment or model supports an explicit compaction command, use it when the context is near 60,000 tokens. If no explicit compaction command is available, internally create and maintain a compact working summary before proceeding.

The compacted summary should be structured like this:

1. Current objective
2. User constraints and preferences
3. Relevant project/files/context
4. Completed work
5. Important findings and command results
6. Open problems
7. Next actions

Always prefer a smaller, accurate context over a large noisy context.
