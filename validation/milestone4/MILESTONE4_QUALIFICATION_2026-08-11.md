# Milestone 4 qualification — 2026-08-11

Milestone 4 qualifies AdverScope's execution and evidence lanes for eight AI-system domains. It does not claim that an arbitrary target can be tested without customer documentation and configuration.

## Result

- 62 bounded controls are represented across M4.1–M4.8.
- 19 controls use qualified native protocol or static-analysis adapters.
- 43 controls use editable customer-configured deterministic evidence contracts.
- Two independent contract fixture families completed secure and vulnerable campaigns for all 43 contract controls.
- The 172 control executions produced 86 true positives, 86 true negatives, no false positives, and no false negatives.
- All 43 vulnerable controls reproduced exactly. The four campaigns retained 344 requests including reproduction.
- Local MCP over `stdio` completed independent secure and vulnerable campaigns with full JSON-RPC custody and exact reproduction.
- Pre-cancelled `stdio` execution retained zero target messages and closed the child; malformed stdout produced an error and no finding.
- Current stateless MCP, Streamable HTTP, and authorized legacy HTTP+SSE regressions remain green.
- The complete regression passed 465 tests in 193.570 seconds with three environment-dependent skips.
- Release identity, JavaScript syntax, dependency-lock, and whitespace checks passed.
- The clean `0.9.0` wheel, source archive, CycloneDX SBOM, release manifest, and SHA-256 checksums were built and verified.
- A fresh Python 3.12 environment installed the release wheel, reported AdverScope `0.9.0`, initialized non-secret state, completed diagnostics with zero failures, and created the isolated synthetic tutorial project.
- The 0.9.0 release candidate passed the complete regression, Windows/Ubuntu/macOS platform matrix, clean installation and release verification, API-only container build, and dependency-security jobs. Public CI runs are authoritative for subsequent tags.

## Finding gate

A configured-contract finding requires all of the following in one immutable run:

1. the exact configured control identifier;
2. the approved case identifier;
3. the immutable fixture SHA-256;
4. the deterministic oracle version;
5. the measured value and acceptance boundary;
6. a non-secret target evidence identifier;
7. a failed security-requirement decision; and
8. exact reproduction.

HTTP success, model prose, an inventory entry, or an unversioned target boolean is not finding evidence.

## Local MCP safety boundary

The `stdio` transport requires an existing absolute executable and an exact SHA-256 digest. AdverScope verifies the digest before every launch, never invokes a shell, materializes only named environment references, bounds response time and output size, retains exact JSON-RPC stdin/stdout, and terminates the child on every exit path. Secret values are not retained.

## Coverage claim

“Qualified” means the documented native adapter or configured deterministic contract lane passed its evidence gates. A control is not tested on a customer target until the required capability, authorized route or executable, identities, fixtures, policy, thresholds, and proof fields are configured in that project.

Multimodal controls use customer-owned immutable fixture references and exact target oracles; AdverScope does not execute embedded media. Privacy and inference controls require approved statistical samples and thresholds. Resource and cost controls require low, customer-approved ceilings and are not load tests. Destructive exploitation remains outside autonomous execution.

Machine-readable evidence is stored in [qualification-2026-08-11.json](qualification-2026-08-11.json).
