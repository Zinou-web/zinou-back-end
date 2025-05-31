-- V3__drop_phone_number_unique_index.sql
-- Drop the unique index on the phone_number column to allow null or empty values
ALTER TABLE `user`
  DROP INDEX `user_phone_number_unique`; 