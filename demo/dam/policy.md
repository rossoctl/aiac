# Organisation access policy for DAM agents

This policy applies to every agent on the DAM platform. An agent's role is described by
the agent's own description, which its owner writes. The tools are the operations of the
MCP servers that the agent holds connections to.

## Direct grants

- An agent may use a tool when its description says the agent does the kind of work the
  tool serves. Reading, listing and searching tools are granted to an agent whose
  description says it reads, reports on, summarizes or triages the resources those tools
  read.

## Prohibitions

- An agent must not use a tool that creates, changes or deletes repositories, branches,
  files, issues, comments, pull requests, reviews or releases, unless its description says
  that the agent makes such changes.
- An agent whose description says that it does not change a kind of resource must not
  use any tool that changes that kind of resource.
- An agent must not use a tool whose effect its description does not cover, or whose
  effect is unknown.
