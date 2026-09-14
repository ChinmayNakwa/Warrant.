"""The guardrail: a model reads an incident's telemetry and answers, and the
answer is checked against an ontology.

`baseline` accepts the model's answer as given. `guarded` sends an answer that
breaks a rule back for repair, then removes whatever still fails.
"""
