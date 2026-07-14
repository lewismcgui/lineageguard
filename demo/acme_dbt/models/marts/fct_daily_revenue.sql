select
    order_date,
    currency,
    cast(count(*) as bigint) as order_count,
    cast(sum(order_total) as decimal(14, 2)) as gross_revenue
from {{ ref('stg_orders') }}
where status = 'completed'
group by order_date, currency
