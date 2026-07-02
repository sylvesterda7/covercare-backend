-- Run this in Supabase SQL Editor
-- Adds worker activation columns for admin review flow

ALTER TABLE workers ADD COLUMN IF NOT EXISTS activated BOOLEAN DEFAULT false;
ALTER TABLE workers ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;
ALTER TABLE workers ADD COLUMN IF NOT EXISTS license_file_url TEXT;
