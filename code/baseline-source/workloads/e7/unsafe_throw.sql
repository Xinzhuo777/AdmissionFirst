-- E7 unsafe_throw client-observation smoke.
-- The runner selects an unauthorized sentinel secret and verifies that
-- unsafe_throw(...) is captured client-side when evaluated before authorization.
SELECT 1 AS e7_unsafe_throw_placeholder;
