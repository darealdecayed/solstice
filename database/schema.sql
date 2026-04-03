CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    key_value VARCHAR(10) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE licenses (
    id SERIAL PRIMARY KEY,
    license_value VARCHAR(10) UNIQUE NOT NULL,
    student_email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_api_keys_key ON api_keys(key_value);
CREATE INDEX idx_licenses_key ON licenses(license_value);
CREATE INDEX idx_licenses_email ON licenses(student_email);
