-- E6b bounded main-tier Sigma ablation workload marker.
--
-- The current E6b runner records deterministic contract-state cases and
-- performance-effect metadata. This file pins the manifest query path for
-- reproducible hashing; full PostgreSQL workload execution is intentionally
-- outside this bounded checkpoint.
SELECT 1 AS e6b_sigma_full_marker;
