-- Branches for facilities
CREATE TABLE IF NOT EXISTS facility_branches (
  id SERIAL PRIMARY KEY,
  facility_email TEXT NOT NULL REFERENCES facilities(email) ON DELETE CASCADE,
  name TEXT NOT NULL,
  city TEXT NOT NULL,
  address TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  phone TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add assigned_to_worker_id and branch_id to shifts
ALTER TABLE shifts ADD COLUMN IF NOT EXISTS assigned_to_worker_id INTEGER REFERENCES workers(id) ON DELETE SET NULL;
ALTER TABLE shifts ADD COLUMN IF NOT EXISTS branch_id INTEGER REFERENCES facility_branches(id) ON DELETE SET NULL;
ALTER TABLE shifts ADD COLUMN IF NOT EXISTS branch_name TEXT;

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_shifts_assigned_worker ON shifts(assigned_to_worker_id);
CREATE INDEX IF NOT EXISTS idx_shifts_branch ON shifts(branch_id);
CREATE INDEX IF NOT EXISTS idx_facility_branches_email ON facility_branches(facility_email);
