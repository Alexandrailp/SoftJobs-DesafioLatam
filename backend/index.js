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

// ==========================================
// MIDDLEWARES
// ==========================================

const reporteConsultas = (req, res, next) => {
  console.log(`\n--- [REPORTE] ${req.method} -> ${req.url} ---`);
  next();
};
app.use(reporteConsultas);

const verificarCredenciales = (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    console.log('❌ Faltan email o password en el body:', req.body);
    return res.status(400).json({ error: 'Email y password son obligatorios' });
  }
  next();
};

const validarToken = (req, res, next) => {
  try {
    const authHeader = req.header('Authorization');
    console.log('[TOKEN] Header Authorization recibido:', authHeader);

    if (!authHeader) {
      console.log('❌ No vino header Authorization');
      return res.status(401).json({ error: 'No se proporcionó token' });
    }

    let token = authHeader.startsWith('Bearer ')
      ? authHeader.split(' ')[1]
      : authHeader;

    token = token ? token.replace(/['"]/g, '').trim() : '';

    if (!token || token === 'null' || token === 'undefined') {
      console.log('❌ El token viene nulo o vacío');
      return res.status(401).json({ error: 'Token inválido' });
    }

    const payload = jwt.verify(token, SECRET_KEY);
    console.log('✅ Token válido. Payload decodificado:', payload);
    req.user = payload;
    next();
  } catch (error) {
    console.log('❌ Error al verificar JWT:', error.message);
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
};

// ==========================================
// RUTAS
// ==========================================

app.post('/usuarios', verificarCredenciales, async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;
    console.log('[REGISTRO] Datos recibidos:', { email, rol, lenguage });

    const passwordEncriptada = bcrypt.hashSync(password, 10);

    const consulta = `
      INSERT INTO usuarios (email, password, rol, lenguage)
      VALUES ($1, $2, $3, $4)
      RETURNING id, email, rol, lenguage
    `;
    const { rows } = await pool.query(consulta, [email, passwordEncriptada, rol, lenguage]);
    console.log('✅ Usuario guardado con éxito en BD:', rows[0]);

    res.status(201).json({ message: 'Usuario registrado con éxito' });
  } catch (error) {
    console.error('❌ Error en INSERT /usuarios:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post('/login', verificarCredenciales, async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('[LOGIN] Intentando ingresar con:', email);

    const { rows, rowCount } = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);

    if (!rowCount) {
      console.log(`❌ No existe el usuario ${email} en la tabla 'usuarios'`);
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const usuario = rows[0];
    const passwordCorrecta = bcrypt.compareSync(password, usuario.password);
    console.log(`[LOGIN] ¿Coincide la clave?: ${passwordCorrecta}`);

    if (!passwordCorrecta) {
      console.log('❌ Contraseña errónea');
      return res.status(401).json({ error: 'Contraseña incorrecta' });
    }

    const token = jwt.sign({ email: usuario.email }, SECRET_KEY, { expiresIn: '2h' });
    console.log('✅ Login exitoso. Token generado y enviado.');
    res.json({ token });
  } catch (error) {
    console.error('❌ Error en POST /login:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.get('/usuarios', validarToken, async (req, res) => {
  try {
    const { email } = req.user;
    console.log('[PERFIL] Buscando datos para:', email);

    const { rows } = await pool.query(
      'SELECT id, email, rol, lenguage FROM usuarios WHERE email = $1',
      [email]
    );

    if (!rows.length) {
      console.log('❌ Usuario autenticado pero no encontrado en BD');
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    console.log('✅ Enviando datos a React:', rows);
    res.json(rows);
  } catch (error) {
    console.error('❌ Error en GET /usuarios:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor activo en http://localhost:${PORT}`);
});