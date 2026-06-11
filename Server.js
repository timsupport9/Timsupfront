const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');
const winston = require('winston');
require('dotenv').config();

// ---------- Configuration & Environment ----------
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

// Required environment variables
const requiredEnvVars = [
  'JWT_SECRET',
  'ADMIN_PASSWORD',
  'FIREBASE_PROJECT_ID',
  'FIREBASE_PRIVATE_KEY',
  'FIREBASE_CLIENT_EMAIL'
];
const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length) {
  console.error(`FATAL: Missing required environment variables: ${missingVars.join(', ')}`);
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:5000'];

// ---------- Winston Logger ----------
const logger = winston.createLogger({
  level: IS_PROD ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    ...(IS_PROD ? [new winston.transports.File({ filename: 'error.log', level: 'error' })] : [])
  ]
});

// ---------- Express App ----------
const app = express();

// ---------- Security & Middleware ----------
app.use(helmet()); // Secure HTTP headers

// CORS – restrict to allowed origins
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', generalLimiter);

// Stricter limiter for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: 'Too many login attempts, please try again later.'
});
app.post('/api/login', loginLimiter);

// Request ID and logging
app.use((req, res, next) => {
  req.id = uuidv4();
  res.setHeader('X-Request-Id', req.id);
  next();
});
app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// ---------- Firebase Admin with Retry ----------
const serviceAccount = {
  projectId: process.env.FIREBASE_PROJECT_ID,
  privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}
const db = admin.firestore();

// Enable Firestore retries
db.settings({
  experimentalForceLongPolling: true, // for Firestore emulator compatibility
  ...(IS_PROD && { ignoreUndefinedProperties: true })
});

// ---------- Helper Functions ----------
function getNextId() {
  return Date.now().toString();
}

// Generic Firestore operations with retry
async function withRetry(fn, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i === retries - 1) throw err;
      logger.warn(`Retry ${i + 1} after error: ${err.message}`);
      await new Promise(resolve => setTimeout(resolve, 100 * (i + 1)));
    }
  }
}

async function getAll(collection, page = 1, limit = 50) {
  let query = db.collection(collection);
  const offset = (page - 1) * limit;
  const snapshot = await withRetry(() => query.offset(offset).limit(limit).get());
  const items = snapshot.docs.map(doc => doc.data());
  // Get total count for pagination metadata (optional)
  const totalSnapshot = await withRetry(() => db.collection(collection).count().get());
  const total = totalSnapshot.data().count;
  return { items, total, page, limit, totalPages: Math.ceil(total / limit) };
}

async function getOne(collection, id) {
  const snapshot = await withRetry(() => db.collection(collection).where('id', '==', id).limit(1).get());
  if (snapshot.empty) return null;
  return snapshot.docs[0].data();
}

async function create(collection, data) {
  const docId = getNextId();
  const newDoc = { id: docId, ...data };
  await withRetry(() => db.collection(collection).doc(docId).set(newDoc));
  return newDoc;
}

async function update(collection, id, data) {
  const snapshot = await withRetry(() => db.collection(collection).where('id', '==', id).limit(1).get());
  if (snapshot.empty) throw new Error('Document not found');
  const docRef = snapshot.docs[0].ref;
  await withRetry(() => docRef.update(data));
  const updated = await docRef.get();
  return updated.data();
}

async function remove(collection, id) {
  const snapshot = await withRetry(() => db.collection(collection).where('id', '==', id).limit(1).get());
  if (!snapshot.empty) {
    await withRetry(() => snapshot.docs[0].ref.delete());
  }
}

// ---------- Input Sanitization ----------
function sanitizeString(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>]/g, ''); // basic XSS protection
}

function sanitizeObject(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  const sanitized = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') sanitized[key] = sanitizeString(value);
    else if (typeof value === 'object') sanitized[key] = sanitizeObject(value);
    else sanitized[key] = value;
  }
  return sanitized;
}

// ---------- Validators ----------
function validateExpert(data) {
  if (!data.name || typeof data.name !== 'string') throw new Error('Name is required');
  if (data.email && !/^\S+@\S+\.\S+$/.test(data.email)) throw new Error('Invalid email format');
  return true;
}
function validateEvent(data) {
  if (!data.title) throw new Error('Title is required');
  if (data.date && isNaN(Date.parse(data.date))) throw new Error('Invalid date format');
  return true;
}
function validateProgram(data) {
  if (!data.title) throw new Error('Title is required');
  return true;
}
function validatePartner(data) {
  if (!data.name) throw new Error('Partner name is required');
  return true;
}
function validateGoal(data) {
  if (!data.title) throw new Error('Goal title is required');
  return true;
}
function validateKPI(data) {
  if (!data.indicator) throw new Error('KPI indicator is required');
  return true;
}
function validateProject(data) {
  if (!data.name) throw new Error('Project name is required');
  return true;
}
function validateAllocation(data) {
  if (!data.partnerId) throw new Error('Partner ID is required');
  if (!data.amount || isNaN(parseFloat(data.amount))) throw new Error('Valid amount is required');
  return true;
}
function validateEventRegistration(data) {
  if (!data.eventId) throw new Error('Event ID is required');
  if (!data.attendeeName) throw new Error('Attendee name is required');
  return true;
}
function validateProgramEnrollment(data) {
  if (!data.programId) throw new Error('Program ID is required');
  if (!data.participantName) throw new Error('Participant name is required');
  return true;
}

// ---------- CRUD Route Factory with validation & sanitization ----------
function createCrudRoutes(entity, collection, validator = null, sanitize = true) {
  // GET all with pagination
  app.get(`/api/${entity}`, async (req, res, next) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = Math.min(parseInt(req.query.limit) || 50, 100);
      const result = await getAll(collection, page, limit);
      res.json(result);
    } catch (err) {
      next(err);
    }
  });

  app.post(`/api/${entity}`, authenticateToken, async (req, res, next) => {
    try {
      let data = sanitize ? sanitizeObject(req.body) : req.body;
      if (validator) validator(data);
      const newItem = await create(collection, data);
      res.status(201).json(newItem);
    } catch (err) {
      next(err);
    }
  });

  app.put(`/api/${entity}/:id`, authenticateToken, async (req, res, next) => {
    try {
      let data = sanitize ? sanitizeObject(req.body) : req.body;
      if (validator) validator(data);
      const updated = await update(collection, req.params.id, data);
      res.json(updated);
    } catch (err) {
      next(err);
    }
  });

  app.delete(`/api/${entity}/:id`, authenticateToken, async (req, res, next) => {
    try {
      await remove(collection, req.params.id);
      res.json({ success: true });
    } catch (err) {
      next(err);
    }
  });
}

// ---------- JWT Authentication ----------
app.post('/api/login', (req, res, next) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid password' });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// ---------- Register all CRUD endpoints ----------
createCrudRoutes('experts', 'experts', validateExpert);
createCrudRoutes('events', 'events', validateEvent);
createCrudRoutes('activities', 'activities');
createCrudRoutes('programs', 'programs', validateProgram);
createCrudRoutes('partners', 'partners', validatePartner);
createCrudRoutes('goals', 'goals', validateGoal);
createCrudRoutes('kpis', 'kpis', validateKPI);
createCrudRoutes('projects', 'projects', validateProject);
createCrudRoutes('allocations', 'allocations', validateAllocation);
createCrudRoutes('eventRegistrations', 'eventRegistrations', validateEventRegistration);
createCrudRoutes('programEnrollments', 'programEnrollments', validateProgramEnrollment);

// ---------- Applications (with type) ----------
app.get('/api/applications/:type', async (req, res, next) => {
  try {
    const snapshot = await db.collection('applications').where('type', '==', req.params.type).get();
    const apps = snapshot.docs.map(doc => doc.data());
    res.json(apps);
  } catch (err) {
    next(err);
  }
});

app.post('/api/applications/:type', authenticateToken, async (req, res, next) => {
  try {
    let { name, email, organization, status } = sanitizeObject(req.body);
    if (!name || !email) throw new Error('Name and email are required');
    const data = { name, email, organization: organization || '', status: status || 'pending', type: req.params.type };
    const newApp = await create('applications', data);
    res.status(201).json(newApp);
  } catch (err) {
    next(err);
  }
});

app.patch('/api/applications/:type/:id', authenticateToken, async (req, res, next) => {
  try {
    const { status } = req.body;
    if (!status || !['pending', 'approved', 'rejected'].includes(status)) {
      throw new Error('Valid status (pending/approved/rejected) required');
    }
    const snapshot = await db.collection('applications').where('id', '==', req.params.id).limit(1).get();
    if (snapshot.empty) return res.status(404).json({ error: 'Not found' });
    await snapshot.docs[0].ref.update({ status });
    const updated = await getOne('applications', req.params.id);
    res.json(updated);
  } catch (err) {
    next(err);
  }
});

// ---------- Special PATCH endpoints ----------
app.patch('/api/eventRegistrations/:id/attend', authenticateToken, async (req, res, next) => {
  try {
    const snapshot = await db.collection('eventRegistrations').where('id', '==', req.params.id).limit(1).get();
    if (snapshot.empty) return res.status(404).json({ error: 'Not found' });
    await snapshot.docs[0].ref.update({ attendance: 'Attended' });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

app.patch('/api/programEnrollments/:id/complete', authenticateToken, async (req, res, next) => {
  try {
    const snapshot = await db.collection('programEnrollments').where('id', '==', req.params.id).limit(1).get();
    if (snapshot.empty) return res.status(404).json({ error: 'Not found' });
    await snapshot.docs[0].ref.update({ completed: 'true' });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// ---------- System Logs ----------
app.get('/api/logs', authenticateToken, async (req, res, next) => {
  try {
    const snapshot = await db.collection('systemLogs').orderBy('timestamp', 'desc').get();
    const logs = snapshot.docs.map(doc => doc.data());
    res.json(logs);
  } catch (err) {
    next(err);
  }
});

app.post('/api/logs', async (req, res, next) => {
  try {
    const { action, message, ...rest } = req.body;
    const logMessage = message || JSON.stringify(rest);
    await create('systemLogs', {
      action: action || 'info',
      message: logMessage,
      timestamp: new Date().toISOString()
    });
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// ---------- Bulk Import ----------
app.post('/api/import', authenticateToken, async (req, res, next) => {
  const data = req.body;
  const collections = ['experts', 'events', 'activities', 'programs', 'partners', 'allocations', 'systemLogs', 'eventRegistrations', 'programEnrollments', 'goals', 'kpis', 'projects'];
  try {
    for (const [key, items] of Object.entries(data)) {
      if (!items || !Array.isArray(items)) continue;
      let colName = key;
      if (key === 'systemLogs') colName = 'systemLogs';
      if (key === 'eventRegistrations') colName = 'eventRegistrations';
      if (key === 'programEnrollments') colName = 'programEnrollments';
      if (key === 'expertApplications' || key === 'corporateApplications' || key === 'membershipApplications') {
        const type = key.replace('Applications', '');
        for (const item of items) {
          await create('applications', { ...item, type });
        }
        continue;
      }
      for (const item of items) {
        await create(colName, sanitizeObject(item));
      }
    }
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// ---------- Homepage extra endpoints ----------
app.get('/api/successStories', async (req, res, next) => {
  try {
    const { items } = await getAll('successStories');
    res.json(items);
  } catch (err) { next(err); }
});
app.get('/api/impactStats', async (req, res, next) => {
  try {
    const { items } = await getAll('impactStats');
    res.json(items);
  } catch (err) { next(err); }
});
app.get('/api/membershipPlans', async (req, res, next) => {
  try {
    const { items } = await getAll('membershipPlans');
    res.json(items);
  } catch (err) { next(err); }
});
app.get('/api/campaigns', async (req, res, next) => {
  try {
    const { items } = await getAll('campaigns');
    res.json(items);
  } catch (err) { next(err); }
});

// ---------- Health Check ----------
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

// ---------- Central Error Handler ----------
app.use((err, req, res, next) => {
  const status = err.status || 500;
  const message = IS_PROD && status === 500 ? 'Internal Server Error' : err.message;
  logger.error(`${req.id} - ${err.stack || err}`);
  res.status(status).json({ error: message, requestId: req.id });
});

// ---------- Seed Default Data (Improved) ----------
async function seedData() {
  const collectionsToSeed = {
    experts: [{ name: "Dr. Sarah Johnson", expertise: "Community Development", email: "sarah@example.com", phone: "+254700111222" }],
    events: [{ title: "Youth Empowerment Summit", date: "2025-07-15", location: "Nairobi", capacity: "200" }],
    programs: [{ title: "Leadership Academy", description: "12-week leadership training", startDate: "2025-06-01", endDate: "2025-08-30" }],
    partners: [{ name: "TechCorp Africa", type: "Corporate", contact: "John Kamau" }],
    successStories: [{ author: "Grace Muthoni", story: "TIMSupport helped me grow my small business.", role: "Entrepreneur" }],
    impactStats: [
      { label: "Communities", value: "12" },
      { label: "Beneficiaries", value: "8200" },
      { label: "Mentors", value: "45" },
      { label: "Partners", value: "32" }
    ],
    membershipPlans: [
      { title: "Supporter", price: "Free", features: "Newsletters, Updates" },
      { title: "Partner", price: "$25/mo", features: "Events, Priority support" },
      { title: "Ambassador", price: "$100/mo", features: "Board access, Annual gala" }
    ],
    campaigns: [{ title: "Education For All", description: "School supplies for 500 children", goal: 50000, raised: 32450 }]
  };

  for (const [col, defaultData] of Object.entries(collectionsToSeed)) {
    const snapshot = await db.collection(col).limit(1).get();
    if (snapshot.empty) {
      for (const item of defaultData) {
        await create(col, item);
      }
      logger.info(`Seeded ${col} collection.`);
    }
  }
}

// ---------- Graceful Shutdown ----------
const server = app.listen(PORT, async () => {
  logger.info(`✅ Server running on http://localhost:${PORT} (${NODE_ENV})`);
  await seedData().catch(err => logger.error(`Seeding error: ${err.message}`));
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received, closing server...');
  server.close(async () => {
    logger.info('Server closed.');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, closing server...');
  server.close(async () => {
    logger.info('Server closed.');
    process.exit(0);
  });
});