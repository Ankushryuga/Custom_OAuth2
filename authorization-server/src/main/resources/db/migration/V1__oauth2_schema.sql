create table if not exists oauth2_registered_client (
    id varchar(100) primary key,
    client_id varchar(100) not null,
    client_id_issued_at timestamp with time zone default now() not null,
    client_secret varchar(200),
    client_secret_expires_at timestamp with time zone,
    client_name varchar(200) not null,
    client_authentication_methods varchar(1000) not null,
    authorization_grant_types varchar(1000) not null,
    redirect_uris varchar(1000),
    scopes varchar(1000) not null,
        post_logout_redirect_uris varchar(4000), -- <-- include this
    client_settings varchar(2000) not null,
    token_settings varchar(2000) not null
);
create unique index if not exists idx_oauth2_registered_client_cid on oauth2_registered_client (client_id);

create table if not exists oauth2_authorization (
    id varchar(100) primary key,
    registered_client_id varchar(100) not null,
    principal_name varchar(200) not null,
    authorization_grant_type varchar(100) not null,
    authorized_scopes varchar(1000),
    attributes text,
    state varchar(500),
    authorization_code_value bytea,
    authorization_code_issued_at timestamp with time zone,
    authorization_code_expires_at timestamp with time zone,
    authorization_code_metadata text,
    access_token_value bytea,
    access_token_issued_at timestamp with time zone,
    access_token_expires_at timestamp with time zone,
    access_token_metadata text,
    access_token_type varchar(100),
    access_token_scopes varchar(1000),
    oidc_id_token_value bytea,
    oidc_id_token_issued_at timestamp with time zone,
    oidc_id_token_expires_at timestamp with time zone,
    oidc_id_token_metadata text,
    refresh_token_value bytea,
    refresh_token_issued_at timestamp with time zone,
    refresh_token_expires_at timestamp with time zone,
    refresh_token_metadata text,
    user_code_value bytea,
    user_code_issued_at timestamp with time zone,
    user_code_expires_at timestamp with time zone,
    user_code_metadata text,
    device_code_value bytea,
    device_code_issued_at timestamp with time zone,
    device_code_expires_at timestamp with time zone,
    device_code_metadata text
);
create index if not exists idx_oauth2_auth_principal on oauth2_authorization (principal_name);
create index if not exists idx_oauth2_auth_registered_client on oauth2_authorization (registered_client_id);

create table if not exists oauth2_authorization_consent (
    registered_client_id varchar(100) not null,
    principal_name varchar(200) not null,
    authorities varchar(1000) not null,
    primary key (registered_client_id, principal_name)
);

--create table if not exists oauth2_registered_client (
--    id varchar(100) primary key,
--    client_id varchar(100) not null,
--    client_id_issued_at timestamp with time zone default now() not null,
--    client_secret varchar(200),
--    client_secret_expires_at timestamp with time zone,
--    client_name varchar(200) not null,
--    client_authentication_methods varchar(1000) not null,
--    authorization_grant_types varchar(1000) not null,
--    redirect_uris varchar(1000),
--    post_logout_redirect_uris varchar(1000), -- <-- include this
--    scopes varchar(1000) not null,
--    client_settings varchar(2000) not null,
--    token_settings varchar(2000) not null
--);
