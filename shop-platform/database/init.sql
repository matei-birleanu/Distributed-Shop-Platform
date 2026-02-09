CREATE DATABASE IF NOT EXISTS shop_db;

DO
$$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_user WHERE usename = 'shop_user') THEN
    CREATE USER shop_user WITH PASSWORD 'shop_password';
  END IF;
END
$$;

GRANT ALL PRIVILEGES ON DATABASE shop_db TO shop_user;

\c shop_db;

GRANT ALL ON SCHEMA public TO shop_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO shop_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO shop_user;

