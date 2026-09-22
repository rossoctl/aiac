#!/usr/bin/env python3
"""The six narrated slides: four intro, one mid-film, one outro.

Each is a PNG in <bundle>/movie/slides/ plus a title, a spoken script, and where it
sits in the film. `at` is the anchor: "intro", "after:11" (immediately after that
task) or "outro". Ordering within an anchor follows this list.

The scripts are what YOU read — they are not captured text, so unlike a task
`summary` they are authored here. Keep them to what the diagrams actually show.
"""

SLIDES = [
    # The opening title card is built by build_title.py rather than supplied as a
    # PNG, so its text tracks the film (21 tasks, the policy) without a re-export.
    dict(id="i0", at="intro", img="title.png",
         title="Onboarding an agent and a tool",
         script="In this demo, we'll walk you through onboarding a new agent and a new "
                "tool onto the platform. We'll go through the entire process manually, "
                "step by step, showing everything that needs to happen for the GitHub "
                "agent and GitHub tool to be compliant with the access control rules "
                "defined in our enterprise policy. Keep in mind the system isn't "
                "necessarily starting from a blank slate: the IdP might already have "
                "existing users with their corporate roles and profile information, and "
                "the platform might have already onboarded a number of agents and tools "
                "before this one. So what you'll see is how this existing state — "
                "including the existing access control rules — affects the newly "
                "deployed agent and tool, and how their onboarding in turn affects that "
                "existing state. The core idea we're demonstrating is a mapping "
                "exercise: using what the system already knows — user IdP profiles, "
                "agent cards, and MCP tools descriptions — together with the policy "
                "itself, we determine which users are authorized to access which agents "
                "and tools, and, just as importantly, which agents and tools each agent "
                "is authorized to access on behalf of the user who invoked it. For "
                "this we scope the decision in an isolated manner and leverage the "
                "reasoning power of an LLM to apply the mapping according to the "
                "policy. We automate the mapping, so the rules never have to be "
                "written by hand."),
    # The source PNG carries a real `kubectl get configmap ...` command from the
    # author's own system on its left half; `crop` removes it and keeps the policy box.
    # Crop is x,y,w,h in source pixels, applied by prep_slides.py.
    dict(id="i1", at="intro", img="AIAC-gh-policy.png",
         crop=(1650, 0, 1900, 441),
         title="The policy — the entire human input",
         script="This is the whole human input to what follows: a two-line policy, "
                "read from a config map. Grant access on a least-privilege basis; "
                "allow only what this policy states; deny by default. Developers may "
                "read and modify source, and read issues. Testers may read and modify "
                "issues. Nobody writes a rule after this."),
    # NOTE (2026-09-17): the recorded i2/i3 takes depart from these scripts — the
    # narrator improvised. Pending a listen in context: either update these to match
    # what was said, or re-record to the script. Until then treat the audio, not this
    # text, as what the film says.
    dict(id="i2", at="intro", img="AIAC-gh-agent-card-mag.png",
         title="The agent — declared skills",
         script="The agent declares two skills in its AgentCard. Source operations: "
                "browse and search code; read, create and modify repository file "
                "contents, branches and commits. And issue operations: read, search, "
                "create and update issues, comments, sub-issues and pull requests."),
    dict(id="i3", at="intro", img="AIAC-gh-tools-descriptions-mag.png",
         title="The tool — capabilities discovered live",
         script="The tool exposes four capabilities. Source read: read repository "
                "contents. Source write: create, modify or delete them, and commit. "
                "Issues read: read issues and their comment threads. And issues write: "
                "create and update issues — open, edit, comment, and close."),
    dict(id="i4", at="intro", img="AIAC-onboarding-state1.png",
         title="State 1 — before onboarding",
         script="This is the system before anything happens. Users exist, with three "
                "of them named: a developer, a tester, and a devops user. The policy "
                "exists. The github agent and the github tool do not — there is no "
                "gate, and nothing connects the users on the left to the tools on the "
                "right."),
    dict(id="s2", at="after:11", img="AIAC-onboarding-state2.png",
         title="State 2 — the agent alone",
         script="The agent is onboarded. Its inbound gate now maps users to agent "
                "scopes: the developer reaches both source and issues, the tester "
                "reaches issues only, and devops gets no grant at all because no role "
                "it holds sources a single agent scope. But no tool is onboarded yet, "
                "so the outbound side is still empty. There is nothing to act on."),
    # State 3 sits at the end of configuration (task 18 is the last task that changes
    # the system), so the three test scenarios then run against a diagram the viewer
    # has just been walked through. The outro that follows is argument alone.
    dict(id="s3", at="after:18", img="AIAC-onboarding-state3.png",
         title="State 3 — after onboarding",
         script="This is how the system looks once the onboarding process has "
                "finished. Both gates are populated. The outbound gate maps users "
                "through the agent to the tool: the developer may read and write "
                "source and read issues, the tester may read and write issues. Devops "
                "sources no agent scope at all. Everything from here on stops changing "
                "the system and just exercises it — three users, against these gates."),
    # The closing argument moves off the State 3 diagram, because it is no longer about
    # this system — it is about what happens at scale. Built by build_outro.py.
    dict(id="o1", at="outro", img="outro.png",
         title="Now scale it",
         script="Onboarding a single agent and a single tool looks simple at first "
                "impression — but in an existing system, we have just seen that it is "
                "not as simple as it may first appear. Now imagine what you would need "
                "in order to onboard an agentic flow that contains three agents and "
                "five tools. This is exactly the problem that AIAC is there to "
                "address."),
]

if __name__ == "__main__":
    for s in SLIDES:
        print(f'{s["id"]:4s} {s["at"]:10s} {len(s["script"].split()):3d}w  {s["title"]}')
    print(f'\n{len(SLIDES)} slides, {sum(len(s["script"].split()) for s in SLIDES)} words')
