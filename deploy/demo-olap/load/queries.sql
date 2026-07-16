-- The analytical workload for the demo-olap stack. Each worker runs this whole
-- file over one connection in a loop (psql -f), so latkit sees nine distinct,
-- genuinely complex statements per pass. Every query uses random() for its
-- runtime cutoffs rather than a baked-in literal: the SQL *text* is identical on
-- every run (one stable row per query on the "Top queries" panel, a clean
-- normalization demo) while the rows scanned and returned vary. \timing prints
-- each query's client-side latency into `docker compose logs load`.
\timing on
\pset pager off

-- Q1  Recursive category tree -> revenue rolled up to the ROOT category, per
--     month, with a running total window. (recursive CTE + window over aggregate)
WITH RECURSIVE tree AS (
    SELECT category_id, category_id AS root_id
    FROM categories WHERE parent_id IS NULL
    UNION ALL
    SELECT c.category_id, t.root_id
    FROM categories c JOIN tree t ON c.parent_id = t.category_id
)
SELECT r.name AS root_category,
       date_trunc('month', o.order_date) AS month,
       round(sum(oi.quantity * oi.unit_price), 2) AS revenue,
       round(sum(sum(oi.quantity * oi.unit_price)) OVER (
                 PARTITION BY r.name ORDER BY date_trunc('month', o.order_date)), 2)
           AS running_revenue
FROM order_items oi
JOIN orders     o ON o.order_id    = oi.order_id
JOIN products   p ON p.product_id  = oi.product_id
JOIN tree       t ON t.category_id = p.category_id
JOIN categories r ON r.category_id = t.root_id
WHERE o.status IN ('paid', 'shipped')
GROUP BY r.name, date_trunc('month', o.order_date)
ORDER BY r.name, month;

-- Q2  Customer monetary quintiles with median / p95 spend. (ntile window feeding
--     an outer GROUP BY + percentile_cont ordered-set aggregates)
WITH spend AS (
    SELECT o.customer_id,
           count(*)                             AS orders,
           sum(oi.quantity * oi.unit_price)     AS monetary
    FROM orders o JOIN order_items oi ON oi.order_id = o.order_id
    GROUP BY o.customer_id
), q AS (
    SELECT customer_id, orders, monetary,
           ntile(5) OVER (ORDER BY monetary) AS quintile
    FROM spend
)
SELECT quintile,
       count(*)                                                        AS customers,
       round(avg(orders), 2)                                           AS avg_orders,
       round(percentile_cont(0.5)  WITHIN GROUP (ORDER BY monetary)::numeric, 2) AS median_spend,
       round(percentile_cont(0.95) WITHIN GROUP (ORDER BY monetary)::numeric, 2) AS p95_spend
FROM q
GROUP BY quintile
ORDER BY quintile;

-- Q3  Country x segment revenue crosstab with subtotals and a grand total, over a
--     randomly sliding date window. (GROUPING SETS + COUNT DISTINCT)
SELECT c.country, c.segment,
       count(DISTINCT o.order_id)                    AS orders,
       round(sum(oi.quantity * oi.unit_price), 2)    AS revenue
FROM customers   c
JOIN orders      o  ON o.customer_id = c.customer_id
JOIN order_items oi ON oi.order_id   = o.order_id
WHERE o.order_date >= DATE '2023-01-01' + (random() * 200)::int
GROUP BY GROUPING SETS ((c.country, c.segment), (c.country), (c.segment), ())
ORDER BY c.country NULLS LAST, c.segment NULLS LAST;

-- Q4  Top-3 products by revenue within each mid-level category. (correlated
--     LATERAL subquery with its own ORDER BY / LIMIT)
SELECT cat.name AS category, top.product_id, round(top.revenue, 2) AS revenue
FROM categories cat
CROSS JOIN LATERAL (
    SELECT p.product_id, sum(oi.quantity * oi.unit_price) AS revenue
    FROM products p JOIN order_items oi ON oi.product_id = p.product_id
    WHERE p.category_id = cat.category_id
    GROUP BY p.product_id
    ORDER BY revenue DESC
    LIMIT 3
) top
WHERE cat.parent_id IS NOT NULL
ORDER BY cat.name, revenue DESC;

-- Q5  Customers spending above their own country's average. (window avg over a
--     partition instead of a per-row correlated subquery)
WITH cust AS (
    SELECT c.customer_id, c.country,
           sum(oi.quantity * oi.unit_price) AS monetary
    FROM customers   c
    JOIN orders      o  ON o.customer_id = c.customer_id
    JOIN order_items oi ON oi.order_id   = o.order_id
    GROUP BY c.customer_id, c.country
)
SELECT customer_id, country, round(monetary, 2) AS monetary, round(country_avg, 2) AS country_avg
FROM (
    SELECT customer_id, country, monetary,
           avg(monetary) OVER (PARTITION BY country) AS country_avg
    FROM cust
) x
WHERE monetary > country_avg
ORDER BY monetary DESC
LIMIT 100;

-- Q6  The full category tree with depth, breadcrumb path and product counts.
--     (recursive CTE building a text path + LEFT JOIN aggregate)
WITH RECURSIVE tree AS (
    SELECT category_id, name, parent_id, 0 AS depth, name::text AS path
    FROM categories WHERE parent_id IS NULL
    UNION ALL
    SELECT c.category_id, c.name, c.parent_id, t.depth + 1, t.path || ' > ' || c.name
    FROM categories c JOIN tree t ON c.parent_id = t.category_id
)
SELECT t.depth, t.path, count(p.product_id) AS products
FROM tree t LEFT JOIN products p ON p.category_id = t.category_id
GROUP BY t.depth, t.path
ORDER BY t.path;

-- Q7  Average gap between a customer's consecutive orders, per segment. (lag()
--     window + FILTER aggregate)
WITH ordered AS (
    SELECT c.segment, o.customer_id, o.order_date,
           lag(o.order_date) OVER (PARTITION BY o.customer_id ORDER BY o.order_date) AS prev_date
    FROM orders o JOIN customers c ON c.customer_id = o.customer_id
)
SELECT segment,
       count(*) FILTER (WHERE prev_date IS NOT NULL) AS repeat_orders,
       round(avg(order_date - prev_date), 1)         AS avg_days_between
FROM ordered
GROUP BY segment
ORDER BY segment;

-- Q8  Orders and revenue across every combination of status and segment. (CUBE)
SELECT o.status, c.segment,
       count(*)                                   AS orders,
       round(sum(oi.quantity * oi.unit_price), 2) AS revenue
FROM orders      o
JOIN customers   c  ON c.customer_id = o.customer_id
JOIN order_items oi ON oi.order_id   = o.order_id
GROUP BY CUBE (o.status, c.segment)
ORDER BY o.status NULLS LAST, c.segment NULLS LAST;

-- Q9  The heavy one: monthly per-category revenue, ranked within each month, with
--     month-over-month deltas — top 10 categories per month. Two chained CTEs, a
--     COUNT DISTINCT, and two window functions (rank + lag). This is the query
--     that reliably lands in latkit's p99 bucket.
WITH monthly AS (
    SELECT date_trunc('month', o.order_date) AS month,
           p.category_id,
           sum(oi.quantity * oi.unit_price)  AS revenue,
           count(DISTINCT o.customer_id)     AS buyers
    FROM orders      o
    JOIN order_items oi ON oi.order_id   = o.order_id
    JOIN products    p  ON p.product_id  = oi.product_id
    WHERE o.status <> 'cancelled'
    GROUP BY 1, 2
), ranked AS (
    SELECT month, category_id, revenue, buyers,
           rank() OVER (PARTITION BY month ORDER BY revenue DESC) AS rnk,
           revenue - lag(revenue) OVER (PARTITION BY category_id ORDER BY month) AS mom_change
    FROM monthly
)
SELECT r.month, cat.name, round(r.revenue, 2) AS revenue, r.buyers, r.rnk,
       round(r.mom_change, 2) AS mom_change
FROM ranked r JOIN categories cat ON cat.category_id = r.category_id
WHERE r.rnk <= 10
ORDER BY r.month, r.rnk;
