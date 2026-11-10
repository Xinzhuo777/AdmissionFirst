-- E8a artifact freshness/context/RID validation gate smoke.
-- The runner renders a validation_gate CTE around caprls_assert_artifact_valid(...)
-- and records reject/fallback/replan/execute actions for each declared scenario.
SELECT 1 AS e8a_artifact_validity_gate_placeholder;
