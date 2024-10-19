const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const cors = require('cors');
const app = express();

app.use(express.json());
app.use(cors());

const secret = 'tu_secreto_jwt';

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'marce1234',
  database: 'Cilsataxi'
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
  return;
}
console.log('Connected to the MySQL database');
});


// Registro
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.query(
    'INSERT INTO users (username, password) VALUES (?, ?)',
    [username, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).send('Error en el registro');
      res.send('Usuario registrado');
    }
  );
});

// Login
app.post('/', (req, res) => {
  const { username, password } = req.body;
  db.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, result) => {
      if (err || result.length === 0) return res.status(400).send('Usuario no encontrado');
      const user = result[0];
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(400).send('Contraseña incorrecta');
      const token = jwt.sign({ userId: user.id }, secret, { expiresIn: '1h' });
      res.json({ token });
    }
  );
});

// Middleware para autenticar
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    jwt.verify(token, secret, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// CRUD de tareas
app.get('/tasks', authenticateJWT, (req, res) => {
  const userId = req.user.userId;
  db.query('SELECT * FROM tasks WHERE user_id = ?', [userId], (err, result) => {
    if (err) return res.status(500).send('Error al obtener tareas');
    res.json(result);
  });
});

app.post('/tasks', authenticateJWT, (req, res) => {
  const { title, description } = req.body;
  const userId = req.user.userId;
  db.query(
    'INSERT INTO tasks (title, description, user_id) VALUES (?, ?, ?)',
    [title, description, userId],
    (err) => {
      if (err) return res.status(500).send('Error al crear tarea');
      res.send('Tarea creada');
    }
  );
});

// Actualizar y eliminar tareas
app.put('/tasks/:id', authenticateJWT, (req, res) => {
  const { title, description, status } = req.body;
  const taskId = req.params.id;
  db.query(
    'UPDATE tasks SET title = ?, description = ?, status = ? WHERE id = ?',
    [title, description, status, taskId],
    (err) => {
      if (err) return res.status(500).send('Error al actualizar tarea');
      res.send('Tarea actualizada');
    }
  );
});

app.delete('/tasks/:id', authenticateJWT, (req, res) => {
  const taskId = req.params.id;
  db.query('DELETE FROM tasks WHERE id = ?', [taskId], (err) => {
    if (err) return res.status(500).send('Error al eliminar tarea');
    res.send('Tarea eliminada');
  });
});

app.listen(5000, () => {
  console.log('Server running on port 5000');
});