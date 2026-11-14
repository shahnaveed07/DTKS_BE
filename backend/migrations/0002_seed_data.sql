-- =============================================================================
-- DTKS (DreamTech Kashmir Solutions) — Initial Reference Data Migration
-- Migration: 0002_seed_data.sql
-- =============================================================================

INSERT OR IGNORE INTO site_settings (setting_key, setting_value)
VALUES (
  'public_settings',
  '{"companyName":"DreamTech Kashmir Solutions","shortName":"DTKS","tagline":"Modern Website Design, Development, Hosting & Maintenance in Kashmir","websiteUrl":"https://dreamtechkashmirsolutions.studio","contactEmail":"contact@dreamtechkashmirsolutions.studio","contactPhone":"+91-000-000-0000","whatsappNumber":"+91-000-000-0000","businessLocation":"Srinagar, Jammu & Kashmir","workingHours":"Monday – Saturday · 10:00 AM – 6:30 PM IST","currency":"INR","socialLinks":{"linkedin":"","github":"","instagram":"","facebook":"","x":""},"budgetOptions":["Under ₹15,000","₹15,000 – ₹30,000","₹30,000 – ₹60,000","₹60,000 – ₹1,00,000","₹1,00,000+","Need a Custom Estimate"],"urgencyOptions":["Standard (3–6 Weeks)","Priority (2–3 Weeks)","Urgent (Under 2 Weeks)","Flexible / Planning Stage"]}'
);
