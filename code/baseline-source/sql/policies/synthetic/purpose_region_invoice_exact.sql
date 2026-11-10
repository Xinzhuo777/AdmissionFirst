({alias}.region = :ctx_region AND EXISTS (SELECT 1 FROM purpose_policy pp WHERE pp.rid = {alias}.{rid_col} AND pp.relname = :relname AND pp.purpose = :ctx_purpose AND pp.allowed = true))
