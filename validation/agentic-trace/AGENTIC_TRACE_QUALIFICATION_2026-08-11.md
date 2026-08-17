# M4.2 structured agent trace qualification

Date: 2026-08-11
Status: **qualified on independent synthetic fixtures; external-platform qualification pending**

## Security requirement

An agent acting for a restricted identity must not cause its executor to complete a denied action. An action that requires human approval must not reach an executed state unless the target-owned approval record is approved.

AdverScope must not accept chatbot prose, an HTTP 200 response, or an LLM evaluator opinion as proof. The verdict comes from configured target-owned planner, approval, and executor fields. A reversible downstream effect additionally requires an authorized before/after verifier and mandatory cleanup.

## Qualification outcome

The independent fixture exposes separate secure and vulnerable implementations and does not receive its expected label from AdverScope. The planner/executor campaign produced one true positive and one true negative, with no false positive or false negative. Precision, recall, specificity, and exact reproduction were all 1.00 for this bounded corpus.

Additional tests passed for approval-bypass verification, mandatory cleanup, zero-traffic cancellation, project isolation, stored-evidence re-evaluation, report trace custody, GUI configuration, preflight readiness, protected-header handling, and rejection of prose-only claims.

The complete AdverScope regression passed **458 tests** in 231.499 seconds. JavaScript syntax validation also passed.

Run the qualification with:

```powershell
python -m unittest tests.test_agentic_trace_security -v
```

The fixture can also be started independently:

```powershell
python scripts/run_agentic_trace_fixture.py --mode secure --port 8101
python scripts/run_agentic_trace_fixture.py --mode vulnerable --port 8102
```

## Supported configuration

- JSON API targets with a normal AdverScope prompt request template.
- `structured-agent-trace-v1` response records.
- Restricted identities with allowed, denied, and approval-required action lists.
- Planner/executor boundary and human-approval bypass cases.
- Read-only authoritative trace confirmation.
- Reversible confirmation through an authorized verifier and cleanup route, followed by post-cleanup verification against the captured baseline.
- Exact HTTP evidence, normalized protocol events, reproduction, report export, and stored-evidence re-evaluation.

## Explicit limitations

This record qualifies only the native structured-trace slice described above. The remaining M4.2 controls are qualified separately through customer-configured deterministic-oracle lanes in `validation/milestone4/qualification-2026-08-11.json`; they are not native structured-trace claims. Independent external agent-platform campaigns remain required before broad production claims.
