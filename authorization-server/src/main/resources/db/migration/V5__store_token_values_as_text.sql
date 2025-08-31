-- Convert token value columns from bytea -> text (safe for string inserts)
ALTER TABLE oauth2_authorization
    ALTER COLUMN authorization_code_value TYPE text USING convert_from(authorization_code_value, 'UTF8'),
    ALTER COLUMN access_token_value       TYPE text USING convert_from(access_token_value, 'UTF8'),
    ALTER COLUMN oidc_id_token_value      TYPE text USING convert_from(oidc_id_token_value, 'UTF8'),
    ALTER COLUMN refresh_token_value      TYPE text USING convert_from(refresh_token_value, 'UTF8'),
    ALTER COLUMN user_code_value          TYPE text USING convert_from(user_code_value, 'UTF8'),
    ALTER COLUMN device_code_value        TYPE text USING convert_from(device_code_value, 'UTF8');

-- Keep metadata/scopes wide
ALTER TABLE oauth2_authorization
    ALTER COLUMN authorization_code_metadata TYPE text,
    ALTER COLUMN access_token_metadata       TYPE text,
    ALTER COLUMN oidc_id_token_metadata      TYPE text,
    ALTER COLUMN refresh_token_metadata      TYPE text,
    ALTER COLUMN user_code_metadata          TYPE text,
    ALTER COLUMN device_code_metadata        TYPE text,
    ALTER COLUMN authorized_scopes           TYPE varchar(4000),
    ALTER COLUMN access_token_scopes         TYPE varchar(4000);
