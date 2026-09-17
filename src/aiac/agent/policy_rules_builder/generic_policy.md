# Generic Access Control Policy (baseline)

This baseline is expressed in the **digested-policy language** and applies to every
policy decision, on top of the scenario policy that follows it. Read both together as one
policy. It contains **only direct grants** and is never a source of prohibitions: a pair
outside an operator role's domain is left ungranted — a silent non-grant — never an
explicit deny.

## Direct grants

- Each of the agent's internal operator roles may perform its target operations within the
  domain it is responsible for, where a target is a tool the agent calls or another agent it
  calls.
