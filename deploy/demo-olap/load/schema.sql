-- demo-olap schema: a small but non-trivial e-commerce star schema, built purely
-- with generate_series so `docker compose up` needs no external data. Sizes are
-- picked so init finishes in a handful of seconds while the analytical queries in
-- queries.sql still do real work (hash joins, big sorts, window scans) — that is
-- what puts a visible tail on latkit's latency panels.
--
--   categories   ~168 rows, a 3-level tree (roots -> mid -> leaf) for recursive CTEs
--   customers     50k   rows, country + segment dimensions
--   products       5k   rows, each in a leaf category
--   orders       300k   rows
--   order_items  ~900k  rows (1..5 lines per order)

BEGIN;

DROP TABLE IF EXISTS order_items, orders, products, customers, categories CASCADE;

-- A category tree: 8 roots, 40 mid-level, 120 leaves. parent_id -> categories,
-- so the recursive CTE in queries.sql has something to walk.
CREATE TABLE categories (
    category_id int PRIMARY KEY,
    name        text NOT NULL,
    parent_id   int REFERENCES categories(category_id)
);
INSERT INTO categories SELECT g,      'root-' || g, NULL              FROM generate_series(1, 8)   g;
INSERT INTO categories SELECT 100 + g, 'mid-'  || g, 1 + (g % 8)      FROM generate_series(1, 40)  g;
INSERT INTO categories SELECT 1000 + g,'leaf-' || g, 101 + (g % 40)   FROM generate_series(1, 120) g;

CREATE TABLE customers (
    customer_id int PRIMARY KEY,
    name        text,
    country     text,
    segment     text,
    signup_date date
);
INSERT INTO customers
SELECT g,
       'customer-' || g,
       (ARRAY['US','DE','FR','GB','JP','BR','IN','CA'])[1 + (random() * 7)::int],
       (ARRAY['consumer','smb','enterprise'])[1 + (random() * 2)::int],
       DATE '2022-01-01' + (random() * 1000)::int
FROM generate_series(1, 50000) g;

-- Products live only in leaf categories (1001..1120).
CREATE TABLE products (
    product_id  int PRIMARY KEY,
    name        text,
    category_id int REFERENCES categories(category_id),
    price       numeric(10, 2)
);
INSERT INTO products
SELECT g,
       'product-' || g,
       1001 + (random() * 119)::int,
       (5 + random() * 495)::numeric(10, 2)
FROM generate_series(1, 5000) g;

CREATE TABLE orders (
    order_id    int PRIMARY KEY,
    customer_id int REFERENCES customers(customer_id),
    order_date  date,
    status      text
);
INSERT INTO orders
SELECT g,
       1 + (random() * 49999)::int,
       DATE '2023-01-01' + (random() * 550)::int,
       (ARRAY['paid','shipped','refunded','cancelled','pending'])[1 + (random() * 4)::int]
FROM generate_series(1, 300000) g;

-- 1..5 lines per order via a LATERAL generate_series -> ~900k rows.
CREATE TABLE order_items (
    order_id   int REFERENCES orders(order_id),
    line_no    int,
    product_id int REFERENCES products(product_id),
    quantity   int,
    unit_price numeric(10, 2)
);
INSERT INTO order_items
SELECT o.order_id,
       gs.line_no,
       1 + (random() * 4999)::int,
       1 + (random() * 9)::int,
       (5 + random() * 495)::numeric(10, 2)
FROM orders o
CROSS JOIN LATERAL generate_series(1, 1 + (random() * 4)::int) AS gs(line_no);

CREATE INDEX ON orders (customer_id);
CREATE INDEX ON orders (order_date);
CREATE INDEX ON order_items (order_id);
CREATE INDEX ON order_items (product_id);
CREATE INDEX ON products (category_id);

COMMIT;

ANALYZE;
