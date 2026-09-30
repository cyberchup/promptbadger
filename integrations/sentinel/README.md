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
  "Direction": "input",
  "User": "jane.doe@contoso.com",
  "SessionId": "c7d1e2f0",
  "verdict": "malicious",
  "score": 77,
  "detections": [
    {"rule_id": "PI-001", "title": "Instruction override - ignore previous instructions",
     "severity": "high", "confidence": 0.9, "matched_text": "Ignore all previous instructions",
     "span": [0, 32], "atlas": ["AML.T0051.000"], "owasp": ["LLM01:2026"]}
  ],
  "input_length": 62,
  "input_sha256": "…",
  "scanner_version": "0.1.0",
  "ruleset_size": 14
}
```

From Python, `scan(text).to_event(source="chat-api", user=upn, session_id=sid)` returns
the same event, so an app that embeds the library can log it directly. The analytics
rule filters on `EventType == "PromptInjectionScan"`, so ship `to_event()` rather than
`to_dict()`.

- `User` and `SessionId` are optional but are what make the SIEM useful: `User` joins
  to `SigninLogs` / `IdentityInfo` and maps to an Account entity, and `SessionId` lets
  hunting query 4 add up weak signals across a conversation.
- `Direction` is `input` for prompts and `output` for model responses. Output scans
  (`scan_output(reply, canaries=[token])`) look for leaks: the system-prompt canary
  coming back, image or link URLs smuggling data to an untrusted host (EchoLeak style),
  and hidden Unicode tag characters. `output_leak.kql` alerts on them.
- The queries read these columns with `column_ifexists()`, so they still run on a table
  created before the columns existed.

OWASP IDs follow the 2026 edition of the LLM Top 10. Events written before promptbadger
moved to it carry 2025 IDs, so every ID's year suffix differs and one ID changed meaning:
`LLM07:2025` (System Prompt Leakage) is `LLM08:2026` (Hidden Context Exposure), while
`LLM07:2026` is Misinformation. If you query across both periods, normalize first:

```kql
| mv-expand detection = detections
| extend owasp = todynamic(replace_string(replace_string(tostring(detection.owasp),
    "LLM07:2025", "LLM08:2026"), ":2025", ":2026"))
```

Raw prompt text is left out by default (it can contain personal data); add
`--include-input` if your retention policy allows it.

## Files

- [`analytics_rule.kql`](analytics_rule.kql): scheduled analytics rule for malicious prompts (input scans)
- [`output_leak.kql`](output_leak.kql): scheduled analytics rule for leaks in model output (canary token,
  zero-click image exfiltration, data-carrying links, ASCII smuggling)
- [`hunting.kql`](hunting.kql): hunting queries for rule noise, probing, technique trends and
  slow-burn conversations (weak signals combined per `SessionId`)
