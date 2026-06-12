const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'voting-system-secret-key-2026';

// ─── CORS ─────────────────────────────────────────────────────────────────────
const allowedOrigins = [
  'http://localhost:5173',
  process.env.FRONTEND_URL,
].filter(Boolean);

app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json());

// ─── Mongoose Connection ──────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/votex';

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch((err) => { console.error('❌ MongoDB connection error:', err.message); process.exit(1); });

// ─── Shared toJSON transform ──────────────────────────────────────────────────
// Maps _id → id and removes __v so the frontend never sees Mongo internals.
const toJSONTransform = {
  virtuals: true,
  versionKey: false,
  transform: (_doc, ret) => {
    ret.id = ret._id.toString();
    delete ret._id;
    return ret;
  },
};

// ─── Mongoose Schemas & Models ────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role:     { type: String, required: true, default: 'voter', enum: ['admin', 'voter'] },
}, { timestamps: { createdAt: 'created_at', updatedAt: false }, toJSON: toJSONTransform });

const User = mongoose.model('User', userSchema);

// ---

const electionSchema = new mongoose.Schema({
  title:       { type: String, required: true },
  description: { type: String, default: '' },
  status:      { type: String, required: true, default: 'upcoming', enum: ['upcoming', 'active', 'completed'] },
  created_by:  { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: { createdAt: 'created_at', updatedAt: false }, toJSON: toJSONTransform });

const Election = mongoose.model('Election', electionSchema);

// ---

const candidateSchema = new mongoose.Schema({
  name:        { type: String, required: true },
  party:       { type: String, required: true },
  photo:       { type: String, default: '' },
  election_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Election', required: true },
}, { toJSON: toJSONTransform });

const Candidate = mongoose.model('Candidate', candidateSchema);

// ---

const voteSchema = new mongoose.Schema({
  voter_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  candidate_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Candidate', required: true },
  election_id:  { type: mongoose.Schema.Types.ObjectId, ref: 'Election', required: true },
  voted_at:     { type: Date, default: Date.now },
}, { toJSON: toJSONTransform });

// Compound unique index: one vote per voter per election
voteSchema.index({ voter_id: 1, election_id: 1 }, { unique: true });

const Vote = mongoose.model('Vote', voteSchema);

// ─── Seed Default Admin ───────────────────────────────────────────────────────
async function seedAdmin() {
  const exists = await User.findOne({ username: 'admin' });
  if (!exists) {
    const hashedPass = bcrypt.hashSync('admin123', 10);
    await User.create({ username: 'admin', password: hashedPass, role: 'admin' });
    console.log('Default admin created: admin / admin123');
  }
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    if (username.length < 3) {
      return res.status(400).json({ success: false, message: 'Username must be at least 3 characters' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }

    const existing = await User.findOne({ username });
    if (existing) {
      return res.status(400).json({ success: false, message: 'Username already exists' });
    }

    const hashedPass = bcrypt.hashSync(password, 10);
    const userRole = role === 'admin' ? 'admin' : 'voter';
    const newUser = await User.create({ username, password: hashedPass, role: userRole });

    const token = jwt.sign({ id: newUser._id.toString(), username, role: userRole }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, user: { id: newUser._id.toString(), username, role: userRole } });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const validPassword = bcrypt.compareSync(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id.toString(), username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token, user: { id: user._id.toString(), username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── Election Routes ──────────────────────────────────────────────────────────
app.get('/api/elections', authenticate, async (req, res) => {
  try {
    const elections = await Election.find().sort({ created_at: -1 }).lean();

    // Attach candidate_count and total_votes for each election
    const enriched = await Promise.all(elections.map(async (e) => {
      const candidate_count = await Candidate.countDocuments({ election_id: e._id });
      const total_votes = await Vote.countDocuments({ election_id: e._id });
      const creator = e.created_by ? await User.findById(e.created_by).select('username').lean() : null;
      return {
        ...e,
        id: e._id.toString(),
        candidate_count,
        total_votes,
        created_by_name: creator?.username || null,
      };
    }));

    // Remove _id from response (frontend expects "id")
    const cleaned = enriched.map(({ _id, __v, ...rest }) => rest);

    res.json({ success: true, elections: cleaned });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/elections', authenticate, adminOnly, async (req, res) => {
  try {
    const { title, description } = req.body;
    if (!title) {
      return res.status(400).json({ success: false, message: 'Election title required' });
    }

    const election = await Election.create({ title, description: description || '', created_by: req.user.id });
    res.json({ success: true, election: election.toJSON() });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/elections/:id/status', authenticate, adminOnly, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['upcoming', 'active', 'completed'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status. Use: upcoming, active, completed' });
    }

    const election = await Election.findById(req.params.id);
    if (!election) {
      return res.status(404).json({ success: false, message: 'Election not found' });
    }

    // If activating, ensure there are at least 2 candidates
    if (status === 'active') {
      const candidateCount = await Candidate.countDocuments({ election_id: req.params.id });
      if (candidateCount < 2) {
        return res.status(400).json({ success: false, message: 'Need at least 2 candidates to start election' });
      }
    }

    election.status = status;
    await election.save();
    res.json({ success: true, election: election.toJSON() });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/elections/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const election = await Election.findById(req.params.id);
    if (!election) {
      return res.status(404).json({ success: false, message: 'Election not found' });
    }
    await Vote.deleteMany({ election_id: req.params.id });
    await Candidate.deleteMany({ election_id: req.params.id });
    await Election.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Election deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── Candidate Routes ─────────────────────────────────────────────────────────
app.get('/api/elections/:id/candidates', authenticate, async (req, res) => {
  try {
    const candidateDocs = await Candidate.find({ election_id: req.params.id }).sort({ _id: 1 }).lean();

    // Attach vote counts
    const candidates = await Promise.all(candidateDocs.map(async (c) => {
      const votes = await Vote.countDocuments({ candidate_id: c._id });
      return { ...c, id: c._id.toString(), votes, _id: undefined, __v: undefined };
    }));

    // Check if current user already voted in this election
    let hasVoted = false;
    if (req.user.role === 'voter') {
      const vote = await Vote.findOne({ voter_id: req.user.id, election_id: req.params.id });
      hasVoted = !!vote;
    }

    res.json({ success: true, candidates, hasVoted });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/elections/:id/candidates', authenticate, adminOnly, async (req, res) => {
  try {
    const { name, party, photo } = req.body;
    if (!name || !party) {
      return res.status(400).json({ success: false, message: 'Candidate name and party required' });
    }

    const election = await Election.findById(req.params.id);
    if (!election) {
      return res.status(404).json({ success: false, message: 'Election not found' });
    }
    if (election.status === 'active') {
      return res.status(400).json({ success: false, message: 'Cannot add candidates to an active election' });
    }

    const candidate = await Candidate.create({ name, party, photo: photo || '', election_id: req.params.id });
    res.json({ success: true, candidate: candidate.toJSON() });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.delete('/api/candidates/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const candidate = await Candidate.findById(req.params.id);
    if (!candidate) {
      return res.status(404).json({ success: false, message: 'Candidate not found' });
    }

    const election = await Election.findById(candidate.election_id);
    if (election && election.status === 'active') {
      return res.status(400).json({ success: false, message: 'Cannot remove candidates from an active election' });
    }

    await Vote.deleteMany({ candidate_id: req.params.id });
    await Candidate.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Candidate removed' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── Vote Route ───────────────────────────────────────────────────────────────
app.post('/api/vote', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'voter') {
      return res.status(403).json({ success: false, message: 'Only voters can cast votes' });
    }

    const { candidateId, electionId } = req.body;
    if (!candidateId || !electionId) {
      return res.status(400).json({ success: false, message: 'Candidate ID and Election ID required' });
    }

    // Check election exists and is active
    const election = await Election.findById(electionId);
    if (!election) {
      return res.status(404).json({ success: false, message: 'Election not found' });
    }
    if (election.status !== 'active') {
      return res.status(400).json({ success: false, message: 'This election is not currently active' });
    }

    // Check candidate exists in this election
    const candidate = await Candidate.findOne({ _id: candidateId, election_id: electionId });
    if (!candidate) {
      return res.status(404).json({ success: false, message: 'Candidate not found in this election' });
    }

    // Check if already voted (application-level guard before the unique index fires)
    const existingVote = await Vote.findOne({ voter_id: req.user.id, election_id: electionId });
    if (existingVote) {
      return res.status(400).json({ success: false, message: 'You have already voted in this election' });
    }

    await Vote.create({ voter_id: req.user.id, candidate_id: candidateId, election_id: electionId });
    res.json({ success: true, message: 'Vote cast successfully!' });
  } catch (err) {
    // Catch the unique index duplicate-key error as a safety net
    if (err.code === 11000) {
      return res.status(400).json({ success: false, message: 'You have already voted in this election' });
    }
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── Results Route ────────────────────────────────────────────────────────────
app.get('/api/elections/:id/results', authenticate, async (req, res) => {
  try {
    const election = await Election.findById(req.params.id);
    if (!election) {
      return res.status(404).json({ success: false, message: 'Election not found' });
    }

    const candidateDocs = await Candidate.find({ election_id: req.params.id }).lean();

    // Attach vote counts and sort by votes descending
    const candidates = await Promise.all(candidateDocs.map(async (c) => {
      const votes = await Vote.countDocuments({ candidate_id: c._id });
      return { ...c, id: c._id.toString(), votes, _id: undefined, __v: undefined };
    }));
    candidates.sort((a, b) => b.votes - a.votes);

    const totalVotes = await Vote.countDocuments({ election_id: req.params.id });

    let hasVoted = false;
    if (req.user.role === 'voter') {
      const vote = await Vote.findOne({ voter_id: req.user.id, election_id: req.params.id });
      hasVoted = !!vote;
    }

    res.json({ success: true, election: election.toJSON(), candidates, totalVotes, hasVoted });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── Admin Stats ──────────────────────────────────────────────────────────────
app.get('/api/admin/stats', authenticate, adminOnly, async (req, res) => {
  try {
    const [totalVoters, totalElections, activeElections, totalCandidates, totalVotes] = await Promise.all([
      User.countDocuments({ role: 'voter' }),
      Election.countDocuments(),
      Election.countDocuments({ status: 'active' }),
      Candidate.countDocuments(),
      Vote.countDocuments(),
    ]);

    const recentElectionDocs = await Election.find().sort({ created_at: -1 }).limit(5).lean();
    const recentElections = await Promise.all(recentElectionDocs.map(async (e) => {
      const candidate_count = await Candidate.countDocuments({ election_id: e._id });
      const total_votes = await Vote.countDocuments({ election_id: e._id });
      const { _id, __v, ...rest } = e;
      return { ...rest, id: _id.toString(), candidate_count, total_votes };
    }));

    res.json({
      success: true,
      stats: { totalVoters, totalElections, activeElections, totalCandidates, totalVotes },
      recentElections,
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ─── Serve React Frontend (Production) ────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'dist')));

// Catch-all: any non-API route serves React's index.html for client-side routing
app.get('/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

// ─── Start Server ─────────────────────────────────────────────────────────────
seedAdmin().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Voting backend running at http://localhost:${PORT}`);
  });
});