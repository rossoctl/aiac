Domain knowledge
- Roles
  - Team trainers: staff responsible for training activities, maintaining rosters and schedules.
  - Performance analysts: staff responsible for assessing and recording player performance.
- Resources
  - Team roster: roster of team members and contact information.
  - Practice schedule: schedule of practice sessions.
  - Player performance evaluations: records of player performance metrics and evaluations.
- Operations
  - Read (lookup): non-mutating retrieval of a resource.
  - Write (update/create/record): creation or modification of a resource.
- Baseline
  - Default-deny: nothing is permitted unless an explicit direct grant below allows it.

Policy statements

Direct grants
- Team trainers may read (lookup) the team roster.
- Team trainers may write (update) the practice schedule.
- Performance analysts may read (lookup) player performance evaluations.
- Performance analysts may write (create or update/record) player performance evaluations.

Attribute invariants
- (none)

Role-assignment constraints
- (none)
