-- E8b bounded main-tier artifact freshness and maintenance workload marker.
--
-- The current E8b runner records deterministic version-check, fallback,
-- refresh, context-scope, and RID-domain maintenance cases. This file pins
-- the manifest query path for reproducible hashing.
SELECT 1 AS e8b_freshness_maintenance_marker;
