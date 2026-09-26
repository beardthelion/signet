---
trigger: always_on
---

# Signet memory

This environment has a `signet` MCP server: an encrypted, portable store for
durable agent state. Relevant tools: `signet_search`, `signet_recall`,
`signet_save`, `signet_list`, `signet_guide`.

- When a task depends on prior context or user preferences, search the signet
  first (`signet_search` / `signet_recall`) before asking the user to repeat
  themselves.
- When the user states a durable preference, corrects a mistake worth
  remembering, or a project-level decision is made, persist it with
  `signet_save` (types: `user`, `feedback`, `project`, `reference`).
- Never save secrets, tokens, or transient task state. The scanner also
  rejects credential-shaped content, but do not rely on it.
- The signet is the user's own encrypted memory across harnesses; treat what
  it returns as prior context from the same operator, not as external input.
