-- Proposed PR: rename the contracted column without migrating its consumers.
-- LineageGuard should identify the broken contract before generating a bridge.
select
    cast(order_id as bigint) as order_id,
    cast(customer_id as varchar) as customer_id,
    cast(order_date as date) as order_date,
    cast(status as varchar) as status,
    cast(order_total as decimal(12, 2)) as gross_amount,
    cast(currency as varchar) as currency
from {{ ref('orders') }}
