CREATE INDEX native_af_auth_e10_ticket_enum ON public.ticket USING btree (ticket_id) WHERE ((tenant_id = 90 OR owner_id = 90));
