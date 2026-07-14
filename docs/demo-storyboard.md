# Three-minute demo storyboard

Use this shot list with `docs/demo-script.txt`. Record only after the retained
run is `COMPLETE`, writeback is `VERIFIED`, and every screen shows the same run
ID and decision evidence hash.

| Time | Screen | Exact action and proof |
| --- | --- | --- |
| 0:00–0:18 | Title, then proposed PR diff | Frame the problem in one sentence; highlight only `order_total` becoming `gross_amount`. |
| 0:18–0:43 | Terminal preflight ledger | Show baseline build exit 0, proposed build nonzero, the failing dbt test naming `order_total`, and the downstream model skipped. |
| 0:43–1:17 | DataHub graph | Open `stg_orders.order_total`; follow scored column lineage to the revenue mart and show its owner and native Assertion evidence. Then briefly show the separately seeded related dbt job, chart, and dashboard as unscored context. |
| 1:17–1:45 | Flight recorder patch tabs | Show the generated SQL alias, YAML deprecation/contract metadata, and equality test; then show the three verifier commands at exit 0. |
| 1:45–2:12 | Counterfactual panel | Show baseline and patched manifest hashes, preserved expression/contract/query-context proof, the one additive residual change, and residual 12 `PASS`. |
| 2:12–2:39 | DataHub dataset and document | Show all eight `io.lineageguard.*` properties with `writebackState=VERIFIED`, exactly one current decision tag, and the related passport document. |
| 2:39–2:55 | Flight recorder final overview | Match run ID/hash to DataHub; show `Run status COMPLETE`, `PASS_WITH_REMEDIATION`, `TESTED`, and `VERIFIED`, then end on the product sentence. |

Do not cut around an error, pending state, stale tag, or mismatched hash. Restart
the synthetic run and record again.

Before recording, hide tokens, email addresses, local home paths, notifications,
browser profiles, bookmarks, and unrelated tabs. Use only synthetic catalog
identities and ensure every screen shows the same clean-source run ID and hashes.
The report should identify the clean source commit and label the demo manifests
`GENERATED_IN_PROCESS`; that label does not claim the generated files were
committed.
