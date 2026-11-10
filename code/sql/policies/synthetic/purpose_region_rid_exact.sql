(:region = :ctx_region AND :class <= :ctx_clearance AND EXISTS (SELECT 1 FROM purpose_policy pp WHERE pp.rid = :__rid AND pp.relname = :relname AND pp.purpose = :ctx_purpose AND pp.allowed = true))
