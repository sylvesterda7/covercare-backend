-- Run this in Supabase SQL Editor.
-- Adds the columns needed for symmetric admin-activation across all three
-- account types (workers already have activated/activated_at from
-- sql-activation.sql) and for client-side ID/passport document tracking.
-- Also reconciles a pre-existing split where facility signup wrote `phone`
-- but the dashboard Settings tab / branches endpoint read and wrote a
-- different column, `contact_phone` — this migrates any contact_phone-only
-- data into `phone` so the column the app now uses everywhere isn't empty.

ALTER TABLE facilities ADD COLUMN IF NOT EXISTS activated BOOLEAN DEFAULT false;
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;

ALTER TABLE clients ADD COLUMN IF NOT EXISTS activated BOOLEAN DEFAULT false;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS id_document_url TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS id_document_type TEXT;

ALTER TABLE workers ADD COLUMN IF NOT EXISTS id_document_type TEXT;

-- Backfill: where a facility only ever had contact_phone set (phone is
-- null/empty), copy it into phone before the app stops reading contact_phone.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'facilities' AND column_name = 'contact_phone'
  ) THEN
    UPDATE facilities
    SET phone = contact_phone
    WHERE (phone IS NULL OR phone = '') AND contact_phone IS NOT NULL AND contact_phone != '';
  END IF;
END $$;
