---
title: promptbadger
emoji: 🦡
colorFrom: red
colorTo: yellow
sdk: gradio
sdk_version: 6.29.0
app_file: app.py
pinned: false
license: mit
short_description: Detection-as-code for LLM prompt injection
---

# promptbadger demo

Paste a prompt to see which detection rules fire, their MITRE ATLAS and OWASP LLM
Top 10 mappings, and the combined 0-100 risk score.

The rules are regex heuristics (v0.1), so obfuscated payloads such as base64 or
leetspeak are expected misses. Source, rule pack and evaluation results:
https://github.com/cyberchup/promptbadger
