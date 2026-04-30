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

CREATE TABLE public.files (
    id integer NOT NULL,
    user_id uuid NOT NULL,
    file_path text NOT NULL,
    datetime timestamp with time zone DEFAULT now() NOT NULL,
    version integer DEFAULT 1 NOT NULL
);

ALTER TABLE public.files ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.files_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.roles (
    id integer NOT NULL,
    name text NOT NULL
);

ALTER TABLE public.roles ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.roles_id_seq
    START WITH 0
    INCREMENT BY 1
    MINVALUE 0
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.sessions (
    id integer NOT NULL,
    user_id uuid NOT NULL,
    session_token uuid DEFAULT gen_random_uuid() NOT NULL,
    user_agent text
);

ALTER TABLE public.sessions ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    login character varying(255) NOT NULL,
    password_hash bytea NOT NULL,
    role_id integer DEFAULT 1 NOT NULL,
    email text,
    salt bytea
);

COPY public.files (id, user_id, file_path, datetime, version) FROM stdin;
\.

COPY public.roles (id, name) FROM stdin;
1	user
2	moderator
3	admin
\.

SELECT pg_catalog.setval('public.files_id_seq', 1, false);

SELECT pg_catalog.setval('public.roles_id_seq', 3, false);

SELECT pg_catalog.setval('public.sessions_id_seq', 1, true);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT email UNIQUE (email);

ALTER TABLE ONLY public.files
    ADD CONSTRAINT files_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT salt UNIQUE (salt);

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT session UNIQUE (session_token);

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT uuid UNIQUE (id);

CREATE INDEX tokens ON public.sessions USING btree (session_token) WITH (deduplicate_items='true');

ALTER TABLE ONLY public.users
    ADD CONSTRAINT roles FOREIGN KEY (role_id) REFERENCES public.roles(id);


ALTER TABLE ONLY public.files
    ADD CONSTRAINT user_id FOREIGN KEY (user_id) REFERENCES public.users(id);


ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT user_id FOREIGN KEY (user_id) REFERENCES public.users(id);

