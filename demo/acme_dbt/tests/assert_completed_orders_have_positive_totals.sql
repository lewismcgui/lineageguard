select order_id, order_total
from {{ ref('stg_orders') }}
where status = 'completed'
  and order_total <= 0
