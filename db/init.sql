-- db/init.sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100) NOT NULL
);

-- Inserción de usuarios de prueba (Contraseñas reales: "admin123" y "user123")
INSERT INTO users (username, password_hash, full_name) VALUES 
('admin', '$2b$10$wT0o3s3Z6R3E4S5T6U7V8.9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O', 'Administrador del Sistema'),
('usuario1', '$2b$10$xU1p4t4a7S4F5T6U7V8W9.0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P', 'Juan Pérez')
ON CONFLICT (username) DO NOTHING;