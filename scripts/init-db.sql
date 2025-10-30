-- Initialize bff-service Service database
-- This script runs during container startup

-- Create database if it doesn't exist (handled by POSTGRES_DB env var)
-- CREATE DATABASE bff_service;

-- Switch to the database
\c bff_service;

-- Create extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Set default timezone
SET timezone = 'UTC';

-- Create example table (this will be handled by Alembic migrations in production)
-- This is here for development/testing purposes
CREATE TABLE IF NOT EXISTS example (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    modified_at TIMESTAMP WITH TIME ZONE,
    version INTEGER DEFAULT 1
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_example_name ON example(name);
CREATE INDEX IF NOT EXISTS idx_example_created_at ON example(created_at);

-- Insert sample data for development
INSERT INTO example (name) VALUES 
    ('Sample Example 1'),
    ('Sample Example 2'),
    ('Sample Example 3')
ON CONFLICT DO NOTHING;

-- Grant permissions (adjust as needed for production)
-- GRANT ALL PRIVILEGES ON DATABASE bff_service TO postgres;
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;