-- Monthly invoices for postpaid facilities
CREATE TABLE IF NOT EXISTS invoices (
  id SERIAL PRIMARY KEY,
  facility_id UUID REFERENCES facilities(id) ON DELETE CASCADE,
  facility_email TEXT NOT NULL,
  facility_name TEXT NOT NULL,
  month INTEGER NOT NULL CHECK (month >= 1 AND month <= 12),
  year INTEGER NOT NULL,
  total_amount NUMERIC NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'overdue', 'cancelled')),
  shift_count INTEGER NOT NULL DEFAULT 0,
  period_start DATE NOT NULL,
  period_end DATE NOT NULL,
  due_date DATE NOT NULL,
  notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  paid_at TIMESTAMP WITH TIME ZONE,
  paid_by TEXT,
  UNIQUE(facility_id, month, year)
);

-- Enable Row Level Security
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;

-- Facility can read only their own invoices
CREATE POLICY "facility_select_own_invoices" ON invoices
  FOR SELECT
  USING (
    auth.jwt() ->> 'email' = facility_email
  );

-- Admin can read all invoices (admins listed in server env, identified by email domain or metadata)
CREATE POLICY "admin_select_all_invoices" ON invoices
  FOR SELECT
  USING (
    auth.jwt() ->> 'email' IN (
      SELECT unnest(string_to_array(current_setting('app.admin_emails', true), ','))
    )
  );

-- Admin can insert/update invoices
CREATE POLICY "admin_insert_invoices" ON invoices
  FOR INSERT
  WITH CHECK (
    auth.jwt() ->> 'email' IN (
      SELECT unnest(string_to_array(current_setting('app.admin_emails', true), ','))
    )
  );

CREATE POLICY "admin_update_invoices" ON invoices
  FOR UPDATE
  USING (
    auth.jwt() ->> 'email' IN (
      SELECT unnest(string_to_array(current_setting('app.admin_emails', true), ','))
    )
  );
