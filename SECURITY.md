# Security policy

## Supported versions

Only the latest release on [PyPI](https://pypi.org/project/promptbadger/) gets fixes.
A fix ships as a new release; older versions are not patched.

## What to report privately

promptbadger runs in the request path of an LLM application, so a flaw in the scanner
itself can hurt the application it is meant to protect. Report these privately:

- **Regex denial of service (ReDoS).** A rule pattern, normalization step or decoder
  that takes super-linear time on crafted input. One slow scan per request is a denial
  of service on whatever sits behind the scanner.
- **Crashes on crafted input.** A `scan()`, `scan_context()` or `scan_output()` call
  that raises instead of returning a verdict. Whether that fails open or closed depends
  on the application, so treat it as a vulnerability.
- **Data going where it shouldn't.** Raw input text in an event without
  `--include-input` / `input_text`, or anything sent to the Anthropic API when the
  judge is off (`Scanner(judge=False)`, the default).
- **Supply chain.** Problems in the packaging, the release workflow or a dependency
  that affect what gets installed from PyPI.

## What to report publicly

**Detection gaps are not vulnerabilities.** A prompt injection or jailbreak that
promptbadger doesn't flag, or an obfuscation its decoders don't undo, is a missed
detection. Every regex and classifier layer has them; the README lists the known ones
under [Known gaps](https://github.com/cyberchup/promptbadger#known-gaps). Open an issue
with the **Missed detection** template so the gap is visible to everyone tuning
against it. The same goes for text the LLM judge closes as benign when it shouldn't.

If you have found a general technique that also gets past other products, a private
report first is welcome too.

## How to report

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/cyberchup/promptbadger/security/advisories/new).
Include the promptbadger version (`promptbadger --version`), the input that triggers
it (for ReDoS, a short script that generates it), and what you observed: scan time
against input length, a traceback, or the event that leaked data.

This is a one-person project. Confirmed issues are fixed in a new release and
published as a GitHub security advisory, crediting the reporter unless they ask
otherwise.
