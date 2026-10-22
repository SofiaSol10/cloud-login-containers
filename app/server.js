const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuración de Sesiones
app.use(session({
  secret: process.env.SESSION_SECRET || 'secreto_super_seguro',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Cambiar a true si se maneja HTTPS directo en app
}));

// Conexión a Base de Datos leyendo variables de entorno
const pool = new Pool(
  process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL }
    : {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        port: process.env.DB_PORT || 5432
      }
);

// Inicialización de la Base de Datos
async function initDB() {
  try {
    // 1. Crear tabla si no existe
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(100) NOT NULL
      );
    `);

    // 2. Generar hashes reales para las contraseñas
    const hashAdmin = await bcrypt.hash('admin123', 10);
    const hashUser1 = await bcrypt.hash('user123', 10);

    // 3. Actualizar o insertar los usuarios con los hashes válidos
    await pool.query(`
      INSERT INTO users (username, password_hash, full_name)
      VALUES 
        ('admin', $1, 'Administrador del Sistema'),
        ('usuario1', $2, 'Juan Pérez')
      ON CONFLICT (username) 
      DO UPDATE SET password_hash = EXCLUDED.password_hash;
    `, [hashAdmin, hashUser1]);

    console.log('Base de datos inicializada y contraseñas actualizadas correctamente');
  } catch (err) {
    console.error('Error al inicializar la base de datos:', err.message);
  }
}
initDB();

// Middleware de Autenticación
function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.redirect('/');
}

// Rutas
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    // Consulta Parametrizada contra Inyección SQL
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const match = await bcrypt.compare(password, user.password_hash);
      if (match) {
        req.session.user = { username: user.username, full_name: user.full_name };
        return res.redirect('/welcome');
      }
    }
    return res.redirect('/?error=1');
  } catch (err) {
    console.error(err);
    return res.redirect('/?error=1');
  }
});

app.get('/welcome', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'welcome.html'));
});

app.get('/api/user', requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Aplicación ejecutándose en el puerto ${PORT}`));