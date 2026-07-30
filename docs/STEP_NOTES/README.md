# Step notes

One file per implementation step, named after its id: `P5.S11.md`, `P6.S01.md`.

A step note **expands the plan; it never replaces it.** `docs/CLAUDE_IMPLEMENTATION_PLAN.md` decides
what a step is and what "done" means. A note breaks that row into sub-tasks, records which AUDIT ids
the step closes and what will guard each one, lists the negative test for every guard, and holds any
question that needs the operator.

Nothing here may renumber a step, add a step, or change what a step means. If the plan looks wrong,
that is a conversation with the operator, not an edit here.

The working contract for the agent writing these is `docs/AGENT_HANDOFF.md`.
