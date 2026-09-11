-- Fixes: "column ... is of type bytea but expression is of type character
-- varying". Spring's stock JdbcOAuth2AuthorizationService.OAuth2Authorization
-- ParametersMapper (used unmodified in AuthorizationServerConfig) always
-- binds attributes/state/*_value/*_metadata as Types.VARCHAR - it never
-- writes raw bytes. V21 typed these as BYTEA, copying the library's
-- MySQL-flavored reference schema, whose BLOB type MySQL silently coerces
-- from VARCHAR. Postgres does not do that implicit cast, hence the error.
-- Switching these columns to TEXT matches what the mapper actually sends.
ALTER TABLE oauth2_authorization
    ALTER COLUMN attributes                    TYPE TEXT USING convert_from(attributes, 'UTF8'),
    ALTER COLUMN authorization_code_value       TYPE TEXT USING convert_from(authorization_code_value, 'UTF8'),
    ALTER COLUMN authorization_code_metadata    TYPE TEXT USING convert_from(authorization_code_metadata, 'UTF8'),
    ALTER COLUMN access_token_value             TYPE TEXT USING convert_from(access_token_value, 'UTF8'),
    ALTER COLUMN access_token_metadata          TYPE TEXT USING convert_from(access_token_metadata, 'UTF8'),
    ALTER COLUMN oidc_id_token_value            TYPE TEXT USING convert_from(oidc_id_token_value, 'UTF8'),
    ALTER COLUMN oidc_id_token_metadata         TYPE TEXT USING convert_from(oidc_id_token_metadata, 'UTF8'),
    ALTER COLUMN refresh_token_value            TYPE TEXT USING convert_from(refresh_token_value, 'UTF8'),
    ALTER COLUMN refresh_token_metadata         TYPE TEXT USING convert_from(refresh_token_metadata, 'UTF8'),
    ALTER COLUMN user_code_value                TYPE TEXT USING convert_from(user_code_value, 'UTF8'),
    ALTER COLUMN user_code_metadata             TYPE TEXT USING convert_from(user_code_metadata, 'UTF8'),
    ALTER COLUMN device_code_value              TYPE TEXT USING convert_from(device_code_value, 'UTF8'),
    ALTER COLUMN device_code_metadata           TYPE TEXT USING convert_from(device_code_metadata, 'UTF8');
