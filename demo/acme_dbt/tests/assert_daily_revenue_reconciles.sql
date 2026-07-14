with expected as (
    select
        cast(order_date as date) as order_date,
        cast(currency as varchar) as currency,
        cast(count(*) as bigint) as order_count,
        cast(sum(order_total) as decimal(14, 2)) as gross_revenue
    from {{ ref('orders') }}
    where status = 'completed'
    group by order_date, currency
),

actual as (
    select order_date, currency, order_count, gross_revenue
    from {{ ref('fct_daily_revenue') }}
)

select
    coalesce(expected.order_date, actual.order_date) as order_date,
    coalesce(expected.currency, actual.currency) as currency,
    expected.order_count as expected_order_count,
    actual.order_count as actual_order_count,
    expected.gross_revenue as expected_gross_revenue,
    actual.gross_revenue as actual_gross_revenue
from expected
full outer join actual using (order_date, currency)
where expected.order_count is distinct from actual.order_count
   or expected.gross_revenue is distinct from actual.gross_revenue
