const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'soft_jobs_secret_key'; 

const pool = new Pool({
  host: 'localhost',
  user: 'postgres',
  password: '1234', 
  database: 'softjobs',
  allowExitOnIdle: true
});

app.use(cors());
app.use(express.json());

//MIDDLEWARES

const reporteConsultas = (req, res, next) => {
  console.log(`[REPORTE] Consulta ${req.method} a la ruta: ${req.url}`);
  next();
};
app.use(reporteConsultas);

const verificarCredenciales = (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Faltan credenciales: email y password son obligatorios' });
  }
  next();
};

const validarToken = (req, res, next) => {
  try {
    const authorizationHeader = req.header('Authorization');
    if (!authorizationHeader) {
      return res.status(401).json({ error: 'Acceso no autorizado: No se proporcionó token' });
    }

    const token = authorizationHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Formato de token inválido' });
    }

    const payload = jwt.verify(token, SECRET_KEY);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
};

//ENDPOINTS

app.post('/usuarios', verificarCredenciales, async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;

    const saltRounds = 10;
    const passwordEncriptada = bcrypt.hashSync(password, saltRounds);

    const consulta = `
      INSERT INTO usuarios (email, password, rol, lenguage)
      VALUES ($1, $2, $3, $4)
      RETURNING id, email, rol, lenguage
    `;
    const values = [email, passwordEncriptada, rol, lenguage];

    await pool.query(consulta, values);
    res.status(201).json({ message: 'Usuario registrado con éxito' });

  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ error: 'Error interno del servidor al registrar usuario' });
  }
});

app.post('/login', verificarCredenciales, async (req, res) => {
  try {
    const { email, password } = req.body;

    const consulta = 'SELECT * FROM usuarios WHERE email = $1';
    const { rows, rowCount } = await pool.query(consulta, [email]);

    if (!rowCount) {
      return res.status(404).json({ error: 'No se encontró ningún usuario con ese email' });
    }

    const usuario = rows[0];

    const passwordCorrecta = bcrypt.compareSync(password, usuario.password);
    if (!passwordCorrecta) {
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    const token = jwt.sign({ email: usuario.email }, SECRET_KEY, { expiresIn: '2h' });

    res.send(token);

  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error interno del servidor en el proceso de autenticación' });
  }
});

app.get('/usuarios', validarToken, async (req, res) => {
  try {
    const { email } = req.user;

    const consulta = 'SELECT id, email, rol, lenguage FROM usuarios WHERE email = $1';
    const { rows } = await pool.query(consulta, [email]);

    if (!rows.length) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(rows);

  } catch (error) {
    console.error('Error al obtener usuario:', error);
    res.status(500).json({ error: 'Error interno del servidor al obtener datos del usuario' });
  }
});

//SERVIDOR

app.listen(PORT, () => {
  console.log(`¡Servidor backend encendido en http://localhost:${PORT}!`);
});