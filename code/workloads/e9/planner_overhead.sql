-- E9 main-tier synthetic planner overhead workload marker.
--
-- The E9 runner generates deterministic memo/state-size overhead records from
-- the tiered manifest axes. This file pins the query path for reproducible
-- hashing.
SELECT 1 AS e9_planner_overhead_marker;
