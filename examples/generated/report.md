# LineageGuard change passport lg-3d10638807e88502

**Run status:** `COMPLETE`  
**Decision:** `PASS_WITH_REMEDIATION`  
**Initial risk:** 88/100 (`BLOCK`)  
**Residual risk:** 12  
**Remediation:** `TESTED`  
**DataHub writeback:** `VERIFIED`  
**Source commit:** `746cab4f54a505130cf63ce42df144e18a1bdab0`  
**Analyzed inputs:** `GENERATED_IN_PROCESS`  
**Decision evidence hash:** `3d10638807e88502181f687002ffbc79c3014a1b262a1e9bf716ad6229870e5f`
**Final artifact hash:** `6dabb578cd762433645d58ebf904c66f81a9625f246ddfe044783bed0ebb203b`

## Proposed schema change

| Relation | Change | Existing | Proposed |
| --- | --- | --- | --- |
| &quot;acme\_commerce&quot;.&quot;analytics\_staging&quot;.&quot;stg\_orders&quot; | rename\_column | order\_total | gross\_amount |

## DataHub blast radius

| Asset | Type | Hops | Owners | Assertions |
| --- | --- | ---: | --- | ---: |
| fct\_daily\_revenue | dataset | 1 | urn:li:corpGroup:finance\_analytics | 1 |

## Tested remediation

Compatibility bridge passed the isolated dbt seed, parse, and build plan.

Verification status: `TESTED`

| Command | Exit | Duration | Output digest |
| --- | ---: | ---: | --- |
| dbt seed --project-dir . --profiles-dir . --no-use-colors | 0 | 2777 ms | 6d54d1fe9d91e32f5750e12a4c36b2e3077511ba090521e1ecbeeb639c0f7424 |
| dbt parse --project-dir . --profiles-dir . --no-use-colors | 0 | 2380 ms | bc09218da36645292c25c1c7d7a960e5cd63aa9fb4dbe42d12b0a05ae89760cc |
| dbt build --project-dir . --profiles-dir . --select stg\_orders+ --no-use-colors | 0 | 3047 ms | 5facd35445a363f6f49afbc43c1412f9f1bd30292600ce7415fcb45061215b63 |

```diff
--- a/models/staging/schema.yml
+++ b/models/staging/schema.yml
@@ -1,54 +1,70 @@
 version: 2
-
 models:
-  - name: stg_orders
-    description: Typed order events forming the stable commerce analytics contract.
+- name: stg_orders
+  description: Typed order events forming the stable commerce analytics contract.
+  config:
+    contract:
+      enforced: true
+    meta:
+      data_owner: commerce_analytics
+      domain: commerce
+      contract_tier: critical
+  columns:
+  - name: order_id
+    data_type: bigint
+    description: Stable synthetic order identifier.
+    data_tests:
+    - not_null
+    - unique
+  - name: customer_id
+    data_type: varchar
+    description: Stable synthetic customer identifier.
+    data_tests:
+    - not_null
+  - name: order_date
+    data_type: date
+    description: UTC calendar date on which the order was placed.
+    data_tests:
+    - not_null
+  - name: status
+    data_type: varchar
+    description: Current order lifecycle state.
+    data_tests:
+    - accepted_values:
+        arguments:
+          values:
+          - completed
+          - pending
+          - cancelled
+          - refunded
+  - name: order_total
+    description: Deprecated compatibility alias. Use `gross_amount` instead.
+    meta:
+      lineageguard:
+        deprecated: true
+        replacement: gross_amount
+        change_id: change-03dc073d2b881401
+    data_type: decimal(12, 2)
+    constraints:
+    - type: not_null
+    data_tests:
+    - not_null
+  - name: currency
+    data_type: varchar
+    description: ISO 4217 settlement currency.
+    data_tests:
+    - accepted_values:
+        arguments:
+          values:
+          - GBP
+  - name: gross_amount
+    data_type: decimal(12, 2)
+    description: Proposed replacement for the contracted order_total column.
+    constraints:
+    - type: not_null
     config:
-      contract:
-        enforced: true
       meta:
-        data_owner: commerce_analytics
-        domain: commerce
-        contract_tier: critical
-    columns:
-      - name: order_id
-        data_type: bigint
-        description: Stable synthetic order identifier.
-        data_tests:
-          - not_null
-          - unique
-      - name: customer_id
-        data_type: varchar
-        description: Stable synthetic customer identifier.
-        data_tests:
-          - not_null
-      - name: order_date
-        data_type: date
-        description: UTC calendar date on which the order was placed.
-        data_tests:
-          - not_null
-      - name: status
-        data_type: varchar
-        description: Current order lifecycle state.
-        data_tests:
-          - accepted_values:
-              arguments:
-                values: ["completed", "pending", "cancelled", "refunded"]
-      - name: gross_amount
-        data_type: decimal(12, 2)
-        description: Proposed replacement for the contracted order_total column.
-        constraints:
-          - type: not_null
-        config:
-          meta:
-            semantic_type: monetary_amount
-            classification: internal
-        data_tests:
-          - not_null
-      - name: currency
-        data_type: varchar
-        description: ISO 4217 settlement currency.
-        data_tests:
-          - accepted_values:
-              arguments:
-                values: ["GBP"]
+        semantic_type: monetary_amount
+        classification: internal
+    data_tests:
+    - not_null
--- a/models/staging/stg_orders.sql
+++ b/models/staging/stg_orders.sql
@@ -1,10 +1,10 @@
--- Proposed PR: rename the contracted column without migrating its consumers.
--- LineageGuard should identify the broken contract before generating a bridge.
-select
-    cast(order_id as bigint) as order_id,
-    cast(customer_id as varchar) as customer_id,
-    cast(order_date as date) as order_date,
-    cast(status as varchar) as status,
-    cast(order_total as decimal(12, 2)) as gross_amount,
-    cast(currency as varchar) as currency
-from {{ ref('orders') }}
+/* Proposed PR: rename the contracted column without migrating its consumers. */ /* LineageGuard should identify the broken contract before generating a bridge. */
+SELECT
+  CAST(order_id AS BIGINT) AS order_id,
+  CAST(customer_id AS TEXT) AS customer_id,
+  CAST(order_date AS DATE) AS order_date,
+  CAST(status AS TEXT) AS status,
+  CAST(order_total AS DECIMAL(12, 2)) AS order_total,
+  CAST(currency AS TEXT) AS currency,
+  CAST(order_total AS DECIMAL(12, 2)) AS gross_amount
+FROM {{ ref('orders') }}
--- /dev/null
+++ b/tests/lineageguard_order_total_matches_gross_amount.sql
@@ -0,0 +1,11 @@
+-- Generated by LineageGuard; no code was executed during generation.
+-- Change: change-03dc073d2b881401
+with compatibility_check as (
+    select
+        order_total,
+        gross_amount
+    from {{ ref('stg_orders') }}
+)
+select *
+from compatibility_check
+where order_total is distinct from gross_amount
```

## Counterfactual decision

Original interface preserved: `true`  
Counterfactual verified: `true`  
Residual decision: `PASS`

## Evidence coverage

- Catalog: `complete`
- Lineage: `complete`
- Traversal: `complete`
- Ownership: `complete`
- Assertions: `complete`

## DataHub durability

The change passport was written through the official MCP server and read back from DataHub.

Document URN: urn:li:document:shared-99a4a464-6f14-4b3c-8794-adb3f60b212e
