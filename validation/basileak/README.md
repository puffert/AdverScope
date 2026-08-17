# OWASP Basileak qualification

This directory records the AdverScope Beta qualification against the public
[OWASP Basileak](https://github.com/OWASP/Basileak) R4 target.

The campaign manifest contains only immutable AdverScope project and run IDs.
The separate oracle describes the expected vulnerability without including a
planted marker, target response, or recovered proof value. Qualification
requires an accepted LLM01 direct-injection finding with retained reproduction
evidence.

Run the scorer against an active local AdverScope instance:

```powershell
python scripts\benchmark_validation.py score `
  --campaign validation\basileak\campaign-qwen38-2026-08-16.json `
  --oracle validation\basileak\oracle-r4.json `
  --api http://127.0.0.1:8091 `
  --json-output validation\basileak\qualification-qwen38-2026-08-16.json `
  --markdown-output validation\basileak\qualification-qwen38-2026-08-16.md `
  --record-adjudications `
  --require-gates
```
