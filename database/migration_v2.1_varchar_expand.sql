-- =====================================================================
-- Migration: Expand VARCHAR sizes to prevent StringDataRightTruncation errors
-- Targets: organizations.name, vendors.name, products.name, vulnerabilities.title
-- DBMS: PostgreSQL 15
-- Safe to run on live environments with existing data preserved.
-- =====================================================================

ALTER TABLE organizations ALTER COLUMN name TYPE VARCHAR(500);
ALTER TABLE vendors ALTER COLUMN name TYPE VARCHAR(500);
ALTER TABLE products ALTER COLUMN name TYPE VARCHAR(500);
ALTER TABLE vulnerabilities ALTER COLUMN title TYPE VARCHAR(500);
