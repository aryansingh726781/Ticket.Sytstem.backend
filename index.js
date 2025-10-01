
require('dotenv').config();
require('express-async-errors'); // allows throwing errors in async handlers
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(cors({
  origin: ["http://localhost:3000", "https://ticket-sytstem-frontend.vercel.app"], // allow localhost + deployed frontend
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], // include OPTIONS
  allowedHeaders: ["Content-Type", "Authorization"], // allow required headers
  credentials: true, // allow cookies/auth headers if you use them
}));

// ✅ Ensure Express handles preflight requests
app.options("*", cors());




// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://aryansingh726781_db_user:JAwzQnSfJ99r8oeg@cluster0.vs3jrul.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0/ticketing';
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const UPLOAD_DIR = process.env.UPLOAD_DIR || 'uploads';

// ensure upload dir exists
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// setup multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2,8)}${ext}`);
  }
});
const upload = multer({ storage });

// optional: nodemailer transporter (if SMTP env provided)
let transporter = null;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

// -----------------------------------------------------------------------------
// Mongoose models
// -----------------------------------------------------------------------------
const { Schema } = mongoose;

const UserSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['user', 'support', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
});
UserSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.passwordHash);
};

const CommentSchema = new Schema({
  author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  attachments: [{ filename: String, path: String, originalName: String }]
});

const TicketSchema = new Schema({
  subject: { type: String, required: true },
  description: { type: String },
  priority: { type: String, enum: ['Low','Medium','High','Urgent'], default: 'Medium' },
  status: { type: String, enum: ['Open','In Progress','Resolved','Closed'], default: 'Open' },
  owner: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  assignee: { type: Schema.Types.ObjectId, ref: 'User', default: null },
  attachments: [{ filename: String, path: String, originalName: String }],
  comments: [CommentSchema],
  history: [{
    action: String,
    by: { type: Schema.Types.ObjectId, ref: 'User' },
    at: { type: Date, default: Date.now },
    meta: Schema.Types.Mixed
  }],
  rating: { type: Number, min: 1, max: 5 },
  feedback: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

TicketSchema.pre('save', function (next) {
  this.updatedAt = new Date();
  next();
});

const User = mongoose.model('User', UserSchema);
const Ticket = mongoose.model('Ticket', TicketSchema);

// -----------------------------------------------------------------------------
// Connect to DB
// -----------------------------------------------------------------------------
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error', err);
    process.exit(1);
  });

// -----------------------------------------------------------------------------
// Helpers & Middleware
// -----------------------------------------------------------------------------
function signToken(user) {
  return jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ message: 'Auth token missing' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.id).select('-passwordHash');
    if (!user) return res.status(401).json({ message: 'Invalid token: user not found' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token', error: err.message });
  }
}

function permit(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ message: 'Not authenticated' });
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden: insufficient permissions' });
    }
    next();
  };
}

async function sendEmailIfPossible({ to, subject, text, html }) {
  if (!transporter) return;
  try {
    await transporter.sendMail({
      from: process.env.FROM_EMAIL || 'no-reply@example.com',
      to,
      subject,
      text,
      html
    });
  } catch (err) {
    console.warn('Failed to send email', err.message);
  }
}

// -----------------------------------------------------------------------------
// Routes: Auth & Users
// -----------------------------------------------------------------------------


app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // validate required fields
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Name, email, and password are required' });
    }

    // check if user already exists
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    // hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // default role is "user"
    let assignedRole = 'user';

    // if client requested support/admin, check if the requester is an admin
    if (role && ['support', 'admin'].includes(role)) {
      if (req.headers.authorization) {
        try {
          const token = req.headers.authorization.split(' ')[1];
          const payload = jwt.verify(token, JWT_SECRET);
          const actor = await User.findById(payload.id);

          if (actor && actor.role === 'admin') {
            assignedRole = role; // allow admin to assign roles
          }
        } catch (err) {
          console.warn('Role escalation blocked:', err.message);
        }
      }
    }

    // create new user
    const user = new User({
      name,
      email,
      passwordHash,
      role: assignedRole,
    

    });

    await user.save();

    // issue token
    const token = signToken(user);

    res.status(201).json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      }
    });

  } catch (err) {
    console.error('❌ Register error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});



app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'email & password required' });
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });
  const ok = await user.comparePassword(password);
  if (!ok) return res.status(400).json({ message: 'Invalid credentials' });
  const token = signToken(user);
  res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
});

// Get current user
app.get('/api/me', authMiddleware, async (req, res) => {
  res.json(req.user);
});

// Admin: add/remove users, list users, assign roles
app.get('/api/admin/users', authMiddleware, permit('admin'), async (req, res) => {
  const users = await User.find().select('-passwordHash');
  res.json(users);
});

app.post('/api/admin/users', authMiddleware, permit('admin'), async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ message: 'Missing fields' });
  if (!['user','support','admin'].includes(role)) return res.status(400).json({ message: 'Invalid role' });
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ message: 'Email exists' });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = new User({ name, email, passwordHash, role });
  await user.save();
  res.status(201).json({ message: 'Created', user: { id: user._id, name: user.name, email: user.email, role: user.role } });
});

app.delete('/api/admin/users/:id', authMiddleware, permit('admin'), async (req, res) => {
  const id = req.params.id;
  if (!id) return res.status(400).json({ message: 'Missing id' });
  await User.findByIdAndDelete(id);
  res.json({ message: 'deleted' });
});

app.patch('/api/admin/users/:id/role', authMiddleware, permit('admin'), async (req, res) => {
  const id = req.params.id;
  const { role } = req.body;
  if (!['user','support','admin'].includes(role)) return res.status(400).json({ message: 'Invalid role' });
  const user = await User.findByIdAndUpdate(id, { role }, { new: true }).select('-passwordHash');
  res.json({ message: 'role updated', user });
});

// -----------------------------------------------------------------------------
// Routes: Tickets
// -----------------------------------------------------------------------------

// Create ticket (user)
app.post('/api/tickets', authMiddleware, permit('user','support','admin'), upload.array('attachments', 6), async (req, res) => {
  const { subject, description, priority, assignee } = req.body;
  if (!subject) return res.status(400).json({ message: 'subject required' });
  const attachments = (req.files || []).map(f => ({ filename: f.filename, path: f.path, originalName: f.originalname }));
  const ticket = new Ticket({
    subject, description, priority: priority || 'Medium',
    owner: req.user._id, assignee: assignee || null,
    attachments
  });
  ticket.history.push({ action: 'Created', by: req.user._id, meta: { priority: ticket.priority } });
  await ticket.save();

  // Notify assignee if present
  if (ticket.assignee) {
    const a = await User.findById(ticket.assignee);
    if (a && a.email) {
      sendEmailIfPossible({
        to: a.email,
        subject: `Ticket assigned: ${ticket.subject}`,
        text: `Ticket #${ticket._id} has been assigned to you.`
      });
    }
  }
  res.status(201).json({ ticket });
});

// Get own tickets (users) or all for support/admin depending on role
app.get('/api/tickets', authMiddleware, async (req, res) => {
  // Query params for search/filter: q (search subject), status, priority, assignee, owner, page, limit
  const { q, status, priority, assignee, owner, page = 1, limit = 20 } = req.query;
  const filter = {};

  // Role-based scoping: regular users see own tickets only
  if (req.user.role === 'user') {
    filter.owner = req.user._id;
  } else {
    // support/admin can optionally filter by owner or assignee
    if (owner) filter.owner = owner;
    if (assignee) filter.assignee = assignee;
  }

  if (status) filter.status = status;
  if (priority) filter.priority = priority;
  if (q) filter.subject = { $regex: q, $options: 'i' };

  const skip = (Number(page) - 1) * Number(limit);
  const tickets = await Ticket.find(filter)
    .populate('owner', 'name email role')
    .populate('assignee', 'name email role')
    .sort({ updatedAt: -1 })
    .skip(skip)
    .limit(Number(limit));

  const total = await Ticket.countDocuments(filter);
  res.json({ total, page: Number(page), limit: Number(limit), tickets });
});








// Get single ticket (if allowed)
app.get('/api/tickets/:id', authMiddleware, async (req, res) => {
  const ticket = await Ticket.findById(req.params.id)
    .populate('owner', 'name email role')
    .populate('assignee', 'name email role')
    .populate('comments.author', 'name email role');

  if (!ticket) return res.status(404).json({ message: 'Ticket not found' });
  // access control: users only their own
  if (req.user.role === 'user' && String(ticket.owner._id) !== String(req.user._id)) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  res.json(ticket);
});

// Add comment to ticket (owner, support, admin; support/admin can comment on any; user only on own)
app.post('/api/tickets/:id/comments', authMiddleware, upload.array('attachments', 4), async (req, res) => {
  const ticket = await Ticket.findById(req.params.id);
  if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

  if (req.user.role === 'user' && String(ticket.owner) !== String(req.user._id)) {
    return res.status(403).json({ message: 'Forbidden' });
  }
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: 'Comment text required' });
  const attachments = (req.files || []).map(f => ({ filename: f.filename, path: f.path, originalName: f.originalname }));
  ticket.comments.push({ author: req.user._id, text, attachments });
  ticket.history.push({ action: 'Comment', by: req.user._id, meta: { textSnippet: text.slice(0, 120) } });
  await ticket.save();

  // notify ticket owner or assignee
  const owner = await User.findById(ticket.owner);
  const assignee = ticket.assignee ? await User.findById(ticket.assignee) : null;
  if (owner && owner.email && String(owner._id) !== String(req.user._id)) {
    sendEmailIfPossible({ to: owner.email, subject: `New comment on ticket ${ticket._id}`, text: `${req.user.name} commented: ${text}` });
  }
  if (assignee && assignee.email && String(assignee._id) !== String(req.user._id)) {
    sendEmailIfPossible({ to: assignee.email, subject: `New comment on ticket ${ticket._id}`, text: `${req.user.name} commented: ${text}` });
  }

  res.json({ message: 'Comment added', ticket });
});

// Change ticket status (support & admin can; owner cannot except to re-open maybe)
// Supported transitions: Open -> In Progress -> Resolved -> Closed
app.patch('/api/tickets/:id/status', authMiddleware, permit('support','admin'), async (req, res) => {
  const { status } = req.body;
  if (!['Open','In Progress','Resolved','Closed'].includes(status)) return res.status(400).json({ message: 'Invalid status' });
  const ticket = await Ticket.findById(req.params.id);
  if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

  ticket.status = status;
  ticket.history.push({ action: 'Status Change', by: req.user._id, meta: { status } });
  await ticket.save();

  // notify owner
  const owner = await User.findById(ticket.owner);
  if (owner && owner.email) {
    sendEmailIfPossible({ to: owner.email, subject: `Ticket ${ticket._id} status: ${status}`, text: `Status changed to ${status}` });
  }

  res.json({ message: 'Status updated', ticket });
});

// Assign or reassign ticket (support or admin can assign - admins can force assign any)
app.patch('/api/tickets/:id/assign', authMiddleware, permit('support','admin'), async (req, res) => {
  const { assigneeId } = req.body;
  const ticket = await Ticket.findById(req.params.id);
  if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

  // if actor is support agent, restrict reassigning? We'll allow support to assign if they are owner or assignee already or admin. Business rule: only admin can force reassign; support can assign to themselves or unassigned.
  if (req.user.role === 'support') {
    // allow support to self-assign
    if (String(req.user._id) !== String(assigneeId) && String(ticket.assignee) && String(ticket.assignee) !== String(req.user._id)) {
      return res.status(403).json({ message: 'Support agents may only assign to themselves or not reassign other agents' });
    }
  }

  const newAssignee = assigneeId ? await User.findById(assigneeId) : null;
  if (assigneeId && !newAssignee) return res.status(400).json({ message: 'Assignee not found' });
  ticket.assignee = newAssignee ? newAssignee._id : null;
  ticket.history.push({ action: 'Assignment', by: req.user._id, meta: { assignee: assigneeId } });
  await ticket.save();

  if (newAssignee && newAssignee.email) {
    sendEmailIfPossible({ to: newAssignee.email, subject: `Ticket ${ticket._id} assigned to you`, text: `You were assigned to ticket "${ticket.subject}"` });
  }
  res.json({ message: 'Assignee updated', ticket });
});

// Owner rates ticket resolution after status is Resolved or Closed
app.post('/api/tickets/:id/rate', authMiddleware, permit('user'), async (req, res) => {
  const { rating, feedback } = req.body;
  if (!rating || rating < 1 || rating > 5) return res.status(400).json({ message: 'rating 1-5 required' });
  const ticket = await Ticket.findById(req.params.id);
  if (!ticket) return res.status(404).json({ message: 'Ticket not found' });
  if (String(ticket.owner) !== String(req.user._id)) return res.status(403).json({ message: 'Only owner can rate' });
  if (!['Resolved','Closed'].includes(ticket.status)) return res.status(400).json({ message: 'Ticket must be Resolved or Closed to rate' });

  ticket.rating = rating;
  if (feedback) ticket.feedback = feedback;
  ticket.history.push({ action: 'Rated', by: req.user._id, meta: { rating, feedback } });
  await ticket.save();
  res.json({ message: 'Rated', ticket });
});

// File download for attachments (simple)
app.get('/api/attachments/:filename', authMiddleware, async (req, res) => {
  const filename = req.params.filename;
  const full = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(full)) return res.status(404).json({ message: 'Not found' });
  res.sendFile(path.resolve(full));
});

// -----------------------------------------------------------------------------
// Admin ticket management (force reassign, resolve/close)
// app.patch('/api/admin/tickets/:id/force', authMiddleware, permit('admin'), async (req, res) => {
//   const { action, assigneeId, status } = req.body;
//   const ticket = await Ticket.findById(req.params.id);
//   if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

//   if (action === 'reassign') {
//     const user = await User.findById(assigneeId);
//     if (!user) return res.status(400).json({ message: 'Assignee not found' });
//     ticket.assignee = user._id;
//     ticket.history.push({ action: 'Force Reassign', by: req.user._id, meta: { assigneeId } });
//   }
//   if (status && ['Open','In Progress','Resolved','Closed'].includes(status)) {
//     ticket.status = status;
//     ticket.history.push({ action: 'Force Status Change', by: req.user._id, meta: { status } });
//   }
//   await ticket.save();
//   res.json({ message: 'Admin action applied', ticket });
// });



app.patch('/api/admin/tickets/:id/force', authMiddleware, permit('admin'), async (req, res) => {
  try {
    const { action, assigneeId, status } = req.body;
    console.log("Admin action request:", { action, assigneeId, status });

    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    if (action === 'reassign') {
      console.log("Reassigning ticket", ticket._id, "to", assigneeId);
      const user = await User.findById(assigneeId);
      if (!user) return res.status(400).json({ message: 'Assignee not found' });
      ticket.assignee = user._id;
      ticket.history.push({ action: 'Force Reassign', by: req.user._id, meta: { assigneeId } });
    }

    if (status && ['Open','In Progress','Resolved','Closed'].includes(status)) {
      ticket.status = status;
      ticket.history.push({ action: 'Force Status Change', by: req.user._id, meta: { status } });
    }

    await ticket.save();
    res.json({ message: 'Admin action applied', ticket });
  } catch (err) {
    console.error("❌ Admin force action error:", err);
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});


// Admin: view all tickets (alias)
app.get('/api/admin/tickets', authMiddleware, permit('admin'), async (req, res) => {
  const { q, status, priority, assignee, owner, page = 1, limit = 50 } = req.query;
  const filter = {};
  if (status) filter.status = status;
  if (priority) filter.priority = priority;
  if (assignee) filter.assignee = assignee;
  if (owner) filter.owner = owner;
  if (q) filter.subject = { $regex: q, $options: 'i' };
  const skip = (Number(page) - 1) * Number(limit);
  const tickets = await Ticket.find(filter)
    .populate('owner', 'name email')
    .populate('assignee', 'name email')
    .sort({ updatedAt: -1 })
    .skip(skip)
    .limit(Number(limit));
  const total = await Ticket.countDocuments(filter);
  res.json({ total, page: Number(page), limit: Number(limit), tickets });
});

// -----------------------------------------------------------------------------
// Misc: health, error handling
// -----------------------------------------------------------------------------
app.get('/', (req, res) => res.send('Ticketing System API is running'));

app.use((err, req, res, next) => {
  console.error(err);
  const status = err.status || 500;
  res.status(status).json({ message: err.message || 'Internal server error', stack: process.env.NODE_ENV === 'production' ? undefined : err.stack });
});

// Start server
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
