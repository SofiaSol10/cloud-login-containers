const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');

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
const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  connectionString: process.env.DATABASE_URL // Utilizado por Blitz Cloud (Opción A)
});

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