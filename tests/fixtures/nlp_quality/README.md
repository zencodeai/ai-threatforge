# NLP Quality Fixtures

These fixture files define versioned golden prompt suites for the deterministic
query workflow.

Files:

- `synthetic_golden.json`
  - Uses synthetic threat/risk fixtures created inside the test.
  - Good for isolated workflow regression checks.
- `example_golden.json`
  - Uses the real example model and checked-in fintech threat/risk artifacts.
  - Good for realistic product-level regression checks.

## Schema

Each fixture file contains:

```json
{
  "thresholds": {
    "answer_nonempty_rate": 1.0,
    "expected_tool_coverage_rate": 1.0
  },
  "cases": [
    {
      "question": "What are the highest risks right now?",
      "expected_tools": ["get_risks"],
      "required_answer_phrases": ["Top risk:", "high"],
      "required_ref_prefixes": ["risk:"],
      "forbidden_tools": ["search_knowledge"],
      "allow_limitations": false
    }
  ]
}
```

Case fields:

- `question`
  - Natural-language prompt sent to `QueryWorkflow.answer()`.
- `expected_tools`
  - Tool names that must appear in the workflow trace.
- `required_answer_phrases`
  - Substrings that must appear in the final composed answer.
- `required_ref_prefixes`
  - Evidence reference prefixes that must be present in `answer.evidence_refs`.
- `forbidden_tools`
  - Optional tools that must not appear in the workflow trace.
- `allow_limitations`
  - Optional boolean. If `false` or omitted, the final answer must not include limitations.

## Metrics

The tests compute suite-level metrics such as:

- `answer_nonempty_rate`
- `expected_tool_coverage_rate`
- `grounded_reference_rate`
- `required_phrase_rate`
- `clean_answer_rate`
- `forbidden_tool_avoidance_rate` (example-artifact suite only)

Thresholds are defined in the fixture file under `thresholds`.

For the current deterministic benchmark suites, thresholds are set to `1.0`.
That means every case must pass every required check.

## Adding Cases

1. Add a new entry to the appropriate JSON fixture.
2. Keep prompts realistic and user-facing.
3. Assert on stable, high-signal phrases rather than brittle full-sentence matches.
4. Prefer evidence-prefix checks over exact evidence-ref lists.
5. Only use `forbidden_tools` when extra tool invocation is truly a regression.

## When To Update

Update these fixtures when:

- routing behavior intentionally changes
- answer wording changes in a meaningful, user-visible way
- new supported query patterns are added
- quality thresholds are deliberately relaxed or tightened

Do not update fixtures just to mask unintended regressions. The fixture changes
should be reviewed as product behavior changes, not only as test maintenance.
