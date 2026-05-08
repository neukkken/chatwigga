const crypto = require('crypto');
const http = require('http');
const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    credentials: false,
  },
});
const PORT = 3000;

const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URL;
if (!mongoUri) {
  console.error('Falta la variable de entorno MONGO_URI.');
  process.exit(1);
}

mongoose
  .connect(mongoUri)
  .then(() => {
    console.log('MongoDB conectado correctamente.');
  })
  .catch((error) => {
    console.error('Error conectando a MongoDB:', error.message);
    process.exit(1);
  });

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      minlength: 2,
      maxlength: 30,
    },
    passwordHash: {
      type: String,
      required: true,
      select: false,
    },
  },
  { timestamps: true }
);

const messageSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 30,
    },
    text: {
      type: String,
      required: true,
      trim: true,
      minlength: 1,
      maxlength: 500,
    },
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

app.use(express.json());
app.use(cors({ origin: '*' }));
app.use(express.static(path.join(__dirname, 'public')));

// Token simple en memoria para prototipo.
const activeTokens = new Map();

function createToken(username) {
  const payload = `${username}:${Date.now()}:${crypto.randomBytes(8).toString('hex')}`;
  return Buffer.from(payload).toString('base64url');
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice('Bearer '.length)
    : null;

  if (!token) {
    return res.status(401).json({ error: 'No autorizado.' });
  }

  const username = activeTokens.get(token);
  if (!username) {
    return res.status(401).json({ error: 'Token invalido o expirado.' });
  }

  req.user = { username };
  next();
}

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;

  if (!token) {
    return next(new Error('No autorizado'));
  }

  const username = activeTokens.get(token);
  if (!username) {
    return next(new Error('Token invalido o expirado'));
  }

  socket.user = { username };
  return next();
});

io.on('connection', (socket) => {
  socket.emit('chat:ready', { ok: true, username: socket.user.username });
});

const rateLimitMax = Number(process.env.CHAT_RATE_LIMIT_MAX || 100);

const chatLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: Number.isFinite(rateLimitMax) ? rateLimitMax : 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: `Has excedido el limite de ${Number.isFinite(rateLimitMax) ? rateLimitMax : 100} mensajes por minuto. Por favor, espera.`,
  },
  keyGenerator: (req) => req.user?.username || req.ip,
});

app.post('/api/login', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!username || username.length < 2 || username.length > 30) {
      return res.status(400).json({
        error: 'El nombre de usuario debe tener entre 2 y 30 caracteres.',
      });
    }

    if (password.length < 6 || password.length > 100) {
      return res.status(400).json({
        error: 'La contrasena debe tener entre 6 y 100 caracteres.',
      });
    }

    const user = await User.findOne({ username }).select('+passwordHash');
    if (!user) {
      return res.status(401).json({ error: 'Usuario o contrasena incorrectos.' });
    }

    if (!user.passwordHash) {
      return res.status(401).json({
        error: 'Este usuario no tiene contrasena. Registralo nuevamente.',
      });
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'Usuario o contrasena incorrectos.' });
    }

    const token = createToken(username);
    activeTokens.set(token, username);

    return res.json({ token, username });
  } catch (error) {
    return res.status(500).json({ error: 'Error interno al iniciar sesion.' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!username || username.length < 2 || username.length > 30) {
      return res.status(400).json({
        error: 'El nombre de usuario debe tener entre 2 y 30 caracteres.',
      });
    }

    if (password.length < 6 || password.length > 100) {
      return res.status(400).json({
        error: 'La contrasena debe tener entre 6 y 100 caracteres.',
      });
    }

    const existingUser = await User.findOne({ username }).select('+passwordHash');
    if (existingUser && existingUser.passwordHash) {
      return res.status(409).json({ error: 'Ese usuario ya existe.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    if (existingUser && !existingUser.passwordHash) {
      existingUser.passwordHash = passwordHash;
      await existingUser.save();
    } else {
      await User.create({ username, passwordHash });
    }

    const token = createToken(username);
    activeTokens.set(token, username);

    return res.status(201).json({ token, username });
  } catch (error) {
    if (error && error.code === 11000) {
      return res.status(409).json({ error: 'Ese usuario ya existe.' });
    }
    return res.status(500).json({ error: 'Error interno al registrar usuario.' });
  }
});

app.get('/api/messages', authMiddleware, async (req, res) => {
  try {
    const messages = await Message.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    return res.json(messages.reverse());
  } catch (error) {
    return res.status(500).json({ error: 'Error al cargar mensajes.' });
  }
});

app.post('/api/messages', authMiddleware, chatLimiter, async (req, res) => {
  try {
    const text = (req.body.text || '').trim();

    if (!text) {
      return res.status(400).json({ error: 'El mensaje no puede estar vacio.' });
    }

    const saved = await Message.create({
      username: req.user.username,
      text,
    });

    io.emit('message:new', {
      _id: saved._id,
      username: saved.username,
      text: saved.text,
      createdAt: saved.createdAt,
      updatedAt: saved.updatedAt,
    });

    return res.status(201).json(saved);
  } catch (error) {
    return res.status(500).json({ error: 'Error al guardar el mensaje.' });
  }
});

app.post('/api/logout', authMiddleware, (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice('Bearer '.length)
    : null;

  if (token) {
    activeTokens.delete(token);
  }

  return res.json({ ok: true });
});

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor corriendo en http://0.0.0.0:${PORT}`);
});
