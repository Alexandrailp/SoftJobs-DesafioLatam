# Desafío Soft Jobs - API REST y Autenticación con JWT

Plataforma backend y frontend para la autenticación y autorización de desarrolladores junior, implementando encriptación de contraseñas con `bcryptjs` y gestión de sesiones mediante tokens `JWT`.

## 🛠️ El proyecto utiliza

* **Backend**: Node.js, Express.js, PostgreSQL (`pg`), JSON Web Tokens (`jsonwebtoken`), BcryptJS (`bcryptjs`), CORS.
* **Frontend**: React 18, Vite, React Router DOM 6, Axios, Bootstrap 5.
* **Base de Datos**: PostgreSQL.

## ⚙️ Configuración 

### 🗄️ Base de Datos (PostgreSQL)

1. Abre tu terminal de PostgreSQL (psql).  
2. Ejecuta el script oficial para crear la base de datos softjobs y la tabla usuarios: 

```sql
CREATE DATABASE softjobs;
\c softjobs;

CREATE TABLE usuarios (
  id SERIAL,
  email VARCHAR(50) NOT NULL,
  password VARCHAR(60) NOT NULL,
  rol VARCHAR(25),
  lenguage VARCHAR(20)
);
```

## 🚀 Instalación y ejecución
- Backend
1. Navega al directorio del backend:
```Bash
cd backend
npm install
node index.js
```
- IMPORTANTE!!💀 Verifica las credenciales de conexión en backend/index.js (usuario, host y contraseña de tu PostgreSQL local).
_Servidor disponible en http://localhost:3000._

- Frontend
1. Abre una segunda terminal y entra a la carpeta del cliente:
```Bash
cd frontend
npm install
npm run dev
```
_La aplicación estará accesible en el navegador en http://localhost:5173._

## 📌 Endpoints Implementados
- POST /usuarios: Registro de usuarios con contraseña encriptada.
- POST /login: Autenticación de credenciales y entrega de token JWT.
- GET /usuarios: Obtención de los datos del usuario autenticado mediante header Authorization: Bearer <token>.

## 🛡️ Middlewares Implementados
- reporteConsultas: Intercepta y reporta en consola cada petición entrante, mostrando el método HTTP y la ruta consultada.
- verificarCredenciales: Valida la presencia obligatoria de los campos email y password en el cuerpo de las solicitudes (POST /usuarios y POST /login), respondiendo con código HTTP 400 si alguno está ausente.
- validarToken: Extrae el token JWT de la cabecera Authorization, verifica su autenticidad contra la firma secreta del servidor y adjunta el payload decodificado a la petición (req.user) para autorizar el acceso.


