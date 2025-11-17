import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';

const prisma = new PrismaClient();
const app = express();

app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGIN, credentials: false }));

// AES-256-GCM helpers
function deriveKey(keyMaterialBase64) {
  const raw = Buffer.from(keyMaterialBase64, 'base64');
  return crypto.createHash('sha256').update(raw).digest();
}
function encryptNumber(num, keyBuf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuf, iv);
  const enc = Buffer.concat([cipher.update(String(num)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: iv.toString('base64'), data: enc.toString('base64'), tag: tag.toString('base64') };
}
function decryptNumber(encObj, keyBuf) {
  const iv = Buffer.from(encObj.iv, 'base64');
  const data = Buffer.from(encObj.data, 'base64');
  const tag = Buffer.from(encObj.tag, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuf, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return Number(dec.toString());
}
function signToken(user) {
  return jwt.sign({ sub: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '12h' });
}
function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Health
app.get('/api/health', (_, res) => res.json({ ok: true }));

// Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const exists = await prisma.user.findUnique({ where: { username } });
  if (exists) return res.status(409).json({ error: 'username taken' });

  const passwordHash = await bcrypt.hash(password, 12);
  const keyMaterial = crypto.randomBytes(32).toString('base64');
  const user = await prisma.user.create({ data: { username, passwordHash, keyMaterial } });

  const keyBuf = deriveKey(keyMaterial);
  const initial = {
    Checking: 162_515_673.60,
    'Premium Checking': 36_114_594.13,
    Savings: 36_114_594.13,
    'Family Savings': 36_114_594.13
  };
  for (const [name, val] of Object.entries(initial)) {
    await prisma.account.create({ data: { userId: user.id, name, encBalance: encryptNumber(val, keyBuf) } });
  }
  res.json({ ok: true });
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  const user = await prisma.user.findUnique({ where: { username } });
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  res.json({ token: signToken(user) });
});

// Balances
app.get('/api/balances', auth, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user.sub } });
  const keyBuf = deriveKey(user.keyMaterial);
  const accounts = await prisma.account.findMany({ where: { userId: user.id } });
  res.json({
    accounts: accounts.map(a => ({
      id: a.id, name: a.name, balance: decryptNumber(a.encBalance, keyBuf)
    }))
  });
});

// Transactions
app.get('/api/transactions', auth, async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.user.sub } });
  const keyBuf = deriveKey(user.keyMaterial);
  const txs = await prisma.transaction.findMany({ where: { userId: user.id }, orderBy: { date: 'desc' } });
  res.json({
    transactions: txs.map(t => ({
      id: t.id,
      date: t.date,
      accountId: t.accountId,
      type: t.type,
      description: t.description,
      amount: decryptNumber(t.encAmount, keyBuf),
      balanceAfter: decryptNumber(t.encBalanceAfter, keyBuf)
    }))
  });
});

// Transfer
app.post('/api/transfer', auth, async (req, res) => {
  const { fromId, toId, amount } = req.body || {};
  const amt = Number(amount);
  if (!fromId || !toId || !(amt > 0) || fromId === toId)
    return res.status(400).json({ error: 'invalid transfer request' });

  const user = await prisma.user.findUnique({ where: { id: req.user.sub } });
  const keyBuf = deriveKey(user.keyMaterial);

  const fromAcc = await prisma.account.findFirst({ where: { id: fromId, userId: user.id } });
  const toAcc = await prisma.account.findFirst({ where: { id: toId, userId: user.id } });
  if (!fromAcc || !toAcc) return res.status(404).json({ error: 'account not found' });

  const fromBal = decryptNumber(fromAcc.encBalance, keyBuf);
  const toBal = decryptNumber(toAcc.encBalance, keyBuf);
  if (fromBal < amt) return res.status(400).json({ error: 'insufficient funds' });

  const newFrom = fromBal - amt;
  const newTo = toBal + amt;

  await prisma.$transaction([
    prisma.account.update({ where: { id:
