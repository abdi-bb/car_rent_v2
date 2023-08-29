DROP TABLE IF EXISTS admin;
DROP TABLE IF EXISTS car;
DROP TABLE IF EXISTS customer;
DROP TABLE IF EXISTS reservation;


CREATE TABLE admin (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE car (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  model TEXT NOT NULL,
  status TEXT NOT NULL,
  seat INTEGER NOT NULL,
  door INTEGER NOT NULL,
  gearbox TEXT NOT NULL,
  image TEXT
);

CREATE TABLE customer (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  address TEXT NOT NULL,
  phone_number TEXT NOT NULL,
  email TEXT NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE reservation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  car_id INTEGER NOT NULL,
  customer_name TEXT NOT NULL,
  pickup_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  dropoff_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  email TEXT NOT NULL,
  password TEXT NOT NULL,
  FOREIGN KEY (customer_id) REFERENCES customer (id),
  FOREIGN KEY (car_id) REFERENCES car (id)
);
