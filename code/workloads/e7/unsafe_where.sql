-- E7 unsafe WHERE direct-observation smoke.
-- The runner renders this logical workload with the full audit signature:
-- unsafe_log(:run_id, :query_id, :plan_id, :occurrence_id, __rid, secret).
SELECT 1 AS e7_unsafe_where_placeholder;
