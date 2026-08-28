--
-- PostgreSQL database dump
--

\restrict XLHIoxASucOeLOLexPwoSf96CyVdutsNxnaHaljWdqa25OYXCK9P4i0dcSTOf38

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: trnm_command_receipts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trnm_command_receipts (
    tenant_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    command_id uuid NOT NULL,
    fingerprint bytea NOT NULL,
    committed_revision bigint NOT NULL,
    committed_state_digest bytea NOT NULL,
    first_sequence bigint,
    last_sequence bigint NOT NULL,
    event_count integer NOT NULL,
    outbox_count integer NOT NULL,
    receipt_bytes bytea NOT NULL,
    receipt_digest bytea NOT NULL,
    committed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT trnm_command_receipts_committed_revision_check CHECK ((committed_revision > 0)),
    CONSTRAINT trnm_command_receipts_committed_state_digest_check CHECK ((octet_length(committed_state_digest) = 32)),
    CONSTRAINT trnm_command_receipts_event_count_check CHECK (((event_count >= 0) AND (event_count <= 64))),
    CONSTRAINT trnm_command_receipts_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT trnm_command_receipts_last_sequence_check CHECK ((last_sequence >= 0)),
    CONSTRAINT trnm_command_receipts_outbox_count_check CHECK (((outbox_count >= 0) AND (outbox_count <= 64))),
    CONSTRAINT trnm_command_receipts_receipt_digest_check CHECK ((octet_length(receipt_digest) = 32)),
    CONSTRAINT trnm_receipt_sequence_shape_ck CHECK ((((event_count = 0) AND (first_sequence IS NULL) AND (last_sequence >= 0)) OR ((event_count > 0) AND (first_sequence IS NOT NULL) AND (first_sequence > 0) AND (last_sequence = ((first_sequence + event_count) - 1)))))
);


--
-- Name: trnm_entity_heads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trnm_entity_heads (
    tenant_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    revision bigint NOT NULL,
    last_sequence bigint NOT NULL,
    authority_generation bigint NOT NULL,
    state_digest bytea NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT trnm_entity_heads_authority_generation_check CHECK ((authority_generation > 0)),
    CONSTRAINT trnm_entity_heads_last_sequence_check CHECK ((last_sequence >= 0)),
    CONSTRAINT trnm_entity_heads_revision_check CHECK ((revision >= 0)),
    CONSTRAINT trnm_entity_heads_state_digest_check CHECK ((octet_length(state_digest) = 32))
);


--
-- Name: trnm_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trnm_events (
    tenant_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    sequence bigint NOT NULL,
    event_id uuid NOT NULL,
    command_id uuid NOT NULL,
    payload_digest bytea NOT NULL,
    payload_bytes bytea NOT NULL,
    recorded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT trnm_events_payload_digest_check CHECK ((octet_length(payload_digest) = 32)),
    CONSTRAINT trnm_events_sequence_check CHECK ((sequence > 0))
);


--
-- Name: trnm_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trnm_outbox (
    tenant_id uuid NOT NULL,
    intent_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    command_id uuid NOT NULL,
    kind text NOT NULL,
    payload_digest bytea NOT NULL,
    payload_bytes bytea NOT NULL,
    attempt integer DEFAULT 0 NOT NULL,
    lease_generation bigint DEFAULT 0 NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    lease_owner uuid,
    lease_expires_at timestamp with time zone,
    applied_receipt_digest bytea,
    dead_letter_reason_digest bytea,
    available_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT trnm_outbox_applied_digest_ck CHECK (((applied_receipt_digest IS NULL) OR (octet_length(applied_receipt_digest) = 32))),
    CONSTRAINT trnm_outbox_attempt_check CHECK (((attempt >= 0) AND (attempt <= 32))),
    CONSTRAINT trnm_outbox_dead_letter_digest_ck CHECK (((dead_letter_reason_digest IS NULL) OR (octet_length(dead_letter_reason_digest) = 32))),
    CONSTRAINT trnm_outbox_kind_check CHECK (((kind <> ''::text) AND (octet_length(kind) <= 128))),
    CONSTRAINT trnm_outbox_lease_generation_check CHECK ((lease_generation >= 0)),
    CONSTRAINT trnm_outbox_payload_digest_check CHECK ((octet_length(payload_digest) = 32)),
    CONSTRAINT trnm_outbox_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'leased'::text, 'applied'::text, 'dead_letter'::text]))),
    CONSTRAINT trnm_outbox_state_shape_ck CHECK ((((state = 'pending'::text) AND (lease_owner IS NULL) AND (lease_expires_at IS NULL) AND (applied_receipt_digest IS NULL) AND (dead_letter_reason_digest IS NULL)) OR ((state = 'leased'::text) AND (lease_owner IS NOT NULL) AND (lease_expires_at IS NOT NULL) AND (lease_generation > 0) AND (applied_receipt_digest IS NULL) AND (dead_letter_reason_digest IS NULL)) OR ((state = 'applied'::text) AND (lease_owner IS NULL) AND (lease_expires_at IS NULL) AND (applied_receipt_digest IS NOT NULL) AND (dead_letter_reason_digest IS NULL)) OR ((state = 'dead_letter'::text) AND (lease_owner IS NULL) AND (lease_expires_at IS NULL) AND (applied_receipt_digest IS NULL) AND (dead_letter_reason_digest IS NOT NULL))))
);


--
-- Name: trnm_schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trnm_schema_migrations (
    profile text NOT NULL,
    version bigint NOT NULL,
    contract_digest bytea NOT NULL,
    applied_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT trnm_schema_migrations_contract_digest_check CHECK ((octet_length(contract_digest) = 32)),
    CONSTRAINT trnm_schema_migrations_version_check CHECK ((version > 0))
);


--
-- Name: trnm_command_receipts trnm_command_receipts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trnm_command_receipts
    ADD CONSTRAINT trnm_command_receipts_pkey PRIMARY KEY (tenant_id, entity_id, command_id);


--
-- Name: trnm_entity_heads trnm_entity_heads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trnm_entity_heads
    ADD CONSTRAINT trnm_entity_heads_pkey PRIMARY KEY (tenant_id, entity_id);


--
-- Name: trnm_events trnm_event_identity_uq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trnm_events
    ADD CONSTRAINT trnm_event_identity_uq UNIQUE (tenant_id, entity_id, event_id);


--
-- Name: trnm_events trnm_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trnm_events
    ADD CONSTRAINT trnm_events_pkey PRIMARY KEY (tenant_id, entity_id, sequence);


--
-- Name: trnm_outbox trnm_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trnm_outbox
    ADD CONSTRAINT trnm_outbox_pkey PRIMARY KEY (tenant_id, intent_id);


--
-- Name: trnm_schema_migrations trnm_schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trnm_schema_migrations
    ADD CONSTRAINT trnm_schema_migrations_pkey PRIMARY KEY (profile, version);


--
-- Name: trnm_events_by_command_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trnm_events_by_command_idx ON public.trnm_events USING btree (tenant_id, entity_id, command_id, sequence);


--
-- Name: trnm_outbox_by_command_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trnm_outbox_by_command_idx ON public.trnm_outbox USING btree (tenant_id, entity_id, command_id, intent_id);


--
-- Name: trnm_outbox_expired_lease_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trnm_outbox_expired_lease_idx ON public.trnm_outbox USING btree (tenant_id, lease_expires_at, intent_id) WHERE (state = 'leased'::text);


--
-- Name: trnm_outbox_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX trnm_outbox_pending_idx ON public.trnm_outbox USING btree (tenant_id, available_at, intent_id) WHERE (state = 'pending'::text);


--
-- Name: trnm_events trnm_event_command_receipt_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trnm_events
    ADD CONSTRAINT trnm_event_command_receipt_fk FOREIGN KEY (tenant_id, entity_id, command_id) REFERENCES public.trnm_command_receipts(tenant_id, entity_id, command_id) ON DELETE RESTRICT;


--
-- Name: trnm_outbox trnm_outbox_command_receipt_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trnm_outbox
    ADD CONSTRAINT trnm_outbox_command_receipt_fk FOREIGN KEY (tenant_id, entity_id, command_id) REFERENCES public.trnm_command_receipts(tenant_id, entity_id, command_id) ON DELETE RESTRICT;


--
-- Name: trnm_command_receipts trnm_receipt_entity_head_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trnm_command_receipts
    ADD CONSTRAINT trnm_receipt_entity_head_fk FOREIGN KEY (tenant_id, entity_id) REFERENCES public.trnm_entity_heads(tenant_id, entity_id) ON DELETE RESTRICT;


--
-- PostgreSQL database dump complete
--

\unrestrict XLHIoxASucOeLOLexPwoSf96CyVdutsNxnaHaljWdqa25OYXCK9P4i0dcSTOf38

