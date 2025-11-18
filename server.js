import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const prisma = new PrismaClient();

app.use(bodyParser.json());
app.use(cors({
  origin: process.env.CORS_ORIGIN || "*"
}));

// 🔑 Register route
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    const user = await prisma.user.create({
      data: {
        username,
        passwordHash,
        keyMaterial: "placeholder-key" // replace with encryption key logic if needed
      }
    });

    res.json({ message: "User registered successfully", userId: user.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed" });
  }
});

// 🔑 Login route
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    // Generate JWT
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h"
    });

    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ✅ Health check route
app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// ✅ Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
