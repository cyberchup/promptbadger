# Microsoft Sentinel integration

`promptbadger scan --jsonl` emits one event per scanned prompt. Ship those events to a
Log Analytics custom table (for example with the Logs Ingestion API, Azure Monitor
Agent reading a JSON log file, or Logstash) and the analytics rule below alerts on them.

The examples assume a custom table named `PromptInjection_CL` with the event's fields
as columns (`verdict`, `score`, `detections`, `Source`, `input_sha256`, ...). The
`detections` column is a dynamic array.

## Event shape

```json
{
  "TimeGenerated": "2026-09-30T18:40:00+00:00",
  "EventType": "PromptInjectionScan",
  "Source": "chat-api",
  "verdict": "malicious",
  "score": 77,
  "detections": [
    {"rule_id": "PI-001", "title": "Instruction override - ignore previous instructions",
     "severity": "high", "confidence": 0.9, "matched_text": "Ignore all previous instructions",
     "span": [0, 32], "atlas": ["AML.T0051.000"], "owasp": ["LLM01:2025"]}
  ],
  "input_length": 62,
  "input_sha256": "…",
  "scanner_version": "0.1.0",
  "ruleset_size": 14
}
```

From Python, `scan(text).to_event(source="chat-api")` returns the same event, so an app
that embeds the library can log it directly. The analytics rule filters on
`EventType == "PromptInjectionScan"`, so ship `to_event()` rather than `to_dict()`.

Raw prompt text is left out by default (it can contain personal data); add
`--include-input` if your retention policy allows it.

## Files

- [`analytics_rule.kql`](analytics_rule.kql): scheduled analytics rule query
- [`hunting.kql`](hunting.kql): hunting queries for tuning and triage
