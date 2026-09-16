# Warrant

Language models are good at reading security logs and bad at admitting what
they did not see. Warrant asks a model what happened in an incident, then
checks every statement in its answer against an ontology and the telemetry
itself. Statements the evidence does not support are sent back for repair and,
if they still fail, removed.

It runs every case two ways so the effect can be measured:

- **Baseline** keeps the model's answer as given.
- **Guarded** checks the answer, asks the model to fix what fails (at most
  twice), removes what still fails, and changes the verdict if what is left no
  longer supports it.

## How it works

1. You file an incident against a *capture*: a recording of Windows Sysmon
   events from one host. You can name the process the alert fired on.
2. The backend picks the events that matter for that process: what it did, the
   processes it started, its ancestors, and what else the host logged at the
   same time. This is the *slice*, capped at 120 events.
3. A model reads the slice in one prompt and returns a verdict, the MITRE
   ATT&CK techniques it sees, and the claims its conclusion rests on. Each
   technique and claim cites the events that show it.
4. The answer is checked with no model involved. It is turned into a small RDF
   graph and validated against SHACL rules:

   | Rule | What it catches |
   |---|---|
   | `technique_unknown`, `technique_retired` | An ATT&CK id that does not exist or is no longer in use |
   | `technique_uncited`, `technique_evidence_kind` | A technique with no evidence, or evidence of the wrong kind |
   | `technique_platform` | A technique ATT&CK does not list for Windows, such as Unix Shell |
   | `technique_indicator` | A technique whose cited events carry no trace of it, such as LSASS dumping cited on events that never name lsass |
   | `event_missing` | A cited event that is not in the telemetry |
   | `type_unknown`, `relation_unknown`, `triple_not_allowed` | A claim the ontology has no words for, such as a file that "spawned" a user |
   | `claim_evidence_kind`, `value_not_in_event` | A claim whose cited event does not actually show it |
   | `claim_technique_unknown` | A claim pointing at a technique id that is not in use |
   | `verdict_malicious_without_technique`, `verdict_benign_with_technique` | A verdict that contradicts the rest of the answer |

5. In guarded mode a failing answer goes back to the model with the list of
   problems. Whatever still fails after two rounds is removed.

Telemetry is attacker-controlled text, so it reaches the model only inside a
fenced block marked as data, and the model's reply is only ever parsed into a
fixed structure. Nothing it says is executed or written to the database
directly.

## Running it

Python 3.12 and Node 20 or later. Run the backend commands from the repo root.

```
# backend
py -3.12 -m venv .venv
./.venv/Scripts/python.exe -m pip install -r backend/requirements.txt
./.venv/Scripts/python.exe -m alembic upgrade head
./.venv/Scripts/python.exe -m scripts.ingest_capture data/captures/small_lab
./.venv/Scripts/python.exe -m uvicorn backend.app:app --reload     # http://localhost:8000

# frontend
cd frontend
npm install
npm run dev                                                         # http://localhost:3000
```

On macOS or Linux the interpreter is `.venv/bin/python`.

### The model

Warrant calls a model through [Ollama](https://ollama.com). Copy
`.env.example` to `.env` and set the model name:

```
# a model running on this machine
WARRANT_OLLAMA_MODEL=qwen3:4b

# or Ollama's hosted API
WARRANT_OLLAMA_MODEL=gpt-oss:120b
WARRANT_OLLAMA_BASE_URL=https://ollama.com
WARRANT_OLLAMA_API_KEY=...
```

With no model set, everything works except starting a run, which answers
`503`. On the hosted path the telemetry leaves your machine.

## Using it

Sign up, open **Incidents**, and file one against a capture. On the incident's
page pick a mode and run it. The page shows the verdict, what the check found
in the model's first answer, what guarded mode removed, the accepted answer
with its claims drawn as a graph, and the events the model read.

**Dashboard** counts your incidents and runs. **Evaluation** shows baseline
against guarded for each model that has been evaluated.

## Evaluation

```
./.venv/Scripts/python.exe -m backend.guardrail.evaluation --repeats 3
./.venv/Scripts/python.exe -m backend.guardrail.evaluation --captures small_lab --repeats 1
./.venv/Scripts/python.exe -m backend.guardrail.evaluation --model gpt-oss:20b
```

This runs every labelled scenario and writes
`data/evaluation/results_<model>.json`, which the Evaluation page reads. A full
pass is one model call or more per scenario per repeat, so it takes a while and
uses hosted credits if you are on the hosted API. Results files are not
committed.

Each scenario is run once per repeat in guarded mode and scored twice. Both
modes start from the same prompt, so the model's first answer is exactly what
baseline would have kept, and the answer left after the check is the guarded
result. Running the two modes separately would compare two different draws
from the model instead of the guardrail's effect.

The results report, for each mode:

- technique precision and recall against the scenario's label
- verdict accuracy, and how many attacks were not dismissed
- how many claims and techniques pass the check
- run by run, whether guarded scored better, worse or the same

## Captures

| Capture | What it is |
|---|---|
| `small_lab` | 13 hand-written synthetic Sysmon events: a malicious PowerShell chain, an LSASS dump, and a benign admin session |
| `real_atomic` | Two real attack recordings merged into one capture |
| `otrf_*` (15) | One real recording each, covering credential dumping, UAC bypasses, persistence and more |

The real captures come from
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (MIT
licence). Each capture directory holds `events.jsonl`, a `manifest.json`
describing it, and a `labels.json` with the expected verdict and techniques.
`scripts/fetch_otrf_capture.py` builds a capture from an OTRF recording.

The ATT&CK technique list in `backend/guardrail/ontology/attack.ttl` is
generated from MITRE's published data by `scripts/build_attack_ontology.py`.
`indicators.ttl` beside it is written by hand: for 37 techniques that
have a signature of their own (a named binary, a registry key, a file), the
text one of the cited events must contain. A technique with no entry there is
not checked this way.

## Tests

```
./.venv/Scripts/python.exe -m pytest -q      # backend
cd frontend && npm test                      # frontend
```

The tests use a scripted stand-in for the model, so they need no Ollama and
make no network calls.

## Layout

```
backend/
  app.py, config.py, database.py, models.py, schemas.py
  auth.py              passwords, JWT access tokens, rotating refresh tokens, rate limit
  incidents.py         incident ownership, one run per incident at a time
  dashboard.py         per-user counts
  llm.py               the Ollama call
  telemetry/           Sysmon ingestion and read-only queries
  guardrail/
    slicer.py          which events the model reads
    prompt.py          the prompt, with telemetry fenced as data
    answer.py          the answer's structure
    validator.py       answer + events -> rule violations
    guard.py           the repair prompt, and removing what still fails
    analyst.py         one run, start to finish
    metrics.py         scoring against a label
    evaluation.py      baseline against guarded over every scenario
    ontology/          schema.ttl, attack.ttl, indicators.ttl, shapes.ttl
  routes/              auth, captures, incidents, dashboard, evaluation
  migrations/          Alembic
frontend/              Next.js, TypeScript, Tailwind
scripts/               capture ingestion and data builders
data/captures/         the telemetry
tests/
```

## Licence

MIT. See [LICENSE](LICENSE).
