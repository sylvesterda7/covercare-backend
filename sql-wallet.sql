-- Wallet system for facilities and clients

-- Add balance column to facilities
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS wallet_balance NUMERIC DEFAULT 0;

-- Add balance column to clients
ALTER TABLE clients ADD COLUMN IF NOT EXISTS wallet_balance NUMERIC DEFAULT 0;

-- Wallet transactions audit trail
CREATE TABLE IF NOT EXISTS wallet_transactions (
  id SERIAL PRIMARY KEY,
  user_email TEXT NOT NULL,
  user_type TEXT NOT NULL CHECK (user_type IN ('facility', 'client')),
  type TEXT NOT NULL CHECK (type IN ('deposit', 'deduction', 'refund', 'withdrawal', 'admin_credit', 'admin_debit')),
  amount NUMERIC NOT NULL CHECK (amount > 0),
  balance_before NUMERIC NOT NULL DEFAULT 0,
  balance_after NUMERIC NOT NULL DEFAULT 0,
  reference TEXT,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'completed' CHECK (status IN ('completed', 'pending', 'failed')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  approved_at TIMESTAMP WITH TIME ZONE,
  approved_by TEXT
);

-- Withdrawal requests
CREATE TABLE IF NOT EXISTS withdrawal_requests (
  id SERIAL PRIMARY KEY,
  user_email TEXT NOT NULL,
  user_type TEXT NOT NULL CHECK (user_type IN ('facility', 'client')),
  amount NUMERIC NOT NULL CHECK (amount > 0),
  bank_name TEXT,
  bank_account_number TEXT,
  bank_account_name TEXT,
  momo_provider TEXT,
  momo_number TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'completed')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  processed_at TIMESTAMP WITH TIME ZONE,
  processed_by TEXT,
  notes TEXT
);
