import { Router, Request, Response } from 'express';
import prisma from '../utils/prisma';
import { supabaseAdmin } from '../middleware/auth'; // Kita import client admin
import bcrypt from 'bcryptjs';
import {z} from 'zod';


const router = Router();

const signupSchema = z.object({
  username: z.string()
    .min(3, "Username minimal 3 karakter")
    .regex(/^[a-zA-Z0-9_]+$/, "Username hanya boleh huruf, angka, dan underscore"),
  email: z.string().email("Format email tidak valid"),
  password: z.string()
    .min(8, "Password minimal 8 karakter")
    .regex(/[A-Z]/, "Harus mengandung huruf besar")
    .regex(/[0-9]/, "Harus mengandung angka")
    .regex(/[^a-zA-Z0-9]/, "Harus mengandung simbol unik (!@#$)"),
});

// --- 1. SIGN UP (Username, Email, Password) ---
router.post('/signup', async (req: Request, res: Response) => {

  const validatedData = signupSchema.parse(req.body);
  const { email, username, password } = validatedData;
  
  if (!email || !username || !password) {
    return res.status(400).json({ error: 'Email, username, dan password wajib diisi.' });
  }

  try {
    // --- Step 1: Buat user di Supabase Auth ---
    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email: email,
      password: password,
      email_confirm: true, // Nanti bisa di-false-kan jika tidak mau verifikasi email
      user_metadata: {
        username: username, // Simpan username di metadata
      },
    });

    if (authError) {
      return res.status(400).json({ error: authError.message });
    }

    const newUserId = authData.user.id;

    // --- Step 2: Hash password untuk DB kita ---
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // --- Step 3: Simpan user di database Prisma (public.users) ---
    const newUser = await prisma.user.create({
      data: {
        id: newUserId, // Pakai ID dari Supabase
        email: email,
        username: username,
        password: hashedPassword, // Simpan hash
      },
    });

    res.status(201).json({ message: 'User berhasil dibuat.', user: newUser });
  
  } catch (error: any) {

    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: error.issues[0].message });
    }

    // Handle jika username/email sudah ada
    if (error.code === 'P2002') { // Kode unik constraint Prisma
      return res.status(400).json({ error: 'Email atau username sudah terdaftar.' });
    }
    
    console.error(error);
    res.status(500).json({ error: 'Gagal membuat user.' });
  }
});

// --- 2. LOGIN (Username + Password) ---
router.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password wajib diisi.' });
  }

  try {
    // --- Step 1: Cari user di DB Prisma ---
    const user = await prisma.user.findUnique({
      where: { username: username },
    });

    if (!user) {
      return res.status(404).json({ error: 'User tidak ditemukan.' });
    }

    // --- Step 2: Cek hash password ---
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Password salah.' });
    }

    // --- Step 3: Jika password cocok, loginkan ke Supabase ---
    // Kita pakai email user (dari DB) dan password (dari request)
    const { data: sessionData, error: sessionError } = await supabaseAdmin.auth.signInWithPassword({
      email: user.email,
      password: password, // Kirim password plain-text ke Supabase
    });

    if (sessionError) {
      return res.status(401).json({ error: sessionError.message });
    }

    // Kirim token dan session ke client (Next.js / Flutter)
    res.status(200).json(sessionData);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Gagal login.' });
  }
});

// --- 3. LOGIN MAGIC LINK (Email Only) ---
router.post('/magic-link', async (req: Request, res: Response) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email wajib diisi.' });
  }

  // Cek dulu apakah user ada di DB
  const user = await prisma.user.findUnique({ where: { email }});
  if (!user) {
    // NOTE: Lo bisa pilih mau otomatis bikin user atau tolak.
    // Saat ini, kita tolak jika emailnya belum terdaftar.
    return res.status(404).json({ error: 'Email tidak terdaftar.' });
  }

  try {
    // --- Step 1: Kirim "OTP" (Magic Link) via email ---
    const { error } = await supabaseAdmin.auth.signInWithOtp({
      email: email,
    });

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    res.status(200).json({ message: 'Magic link telah dikirim ke email Anda.' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Gagal mengirim magic link.' });
  }
});

// [TAMBAHAN BARU] Endpoint Sync Google Login
router.post("/google-sync", async (req, res) => {
  console.log("🔔 [Backend] HIT /google-sync");
  
  const { id, email, username, avatarUrl } = req.body;

  if (!email || !id) {
    return res.status(400).json({ error: "Email and ID are required" });
  }

  try {
    // 1. Cek Email dulu (Prioritas Utama)
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      console.log("ℹ️ [Backend] User email matched, updating...");
      const updatedUser = await prisma.user.update({
        where: { email },
        data: { avatarUrl }, 
      });
      return res.status(200).json({ message: "User synced", user: updatedUser });
    }

    // 2. [LOGIKA BARU] Handle Username Bentrok
    let finalUsername = username || email.split('@')[0];
    
    // Cek apakah username calon ini sudah ada yang punya?
    const checkUsername = await prisma.user.findUnique({
      where: { username: finalUsername }
    });

    if (checkUsername) {
      // Kalau sudah ada, tambahkan 4 digit angka random biar unik
      const randomSuffix = Math.floor(1000 + Math.random() * 9000); // 1000-9999
      finalUsername = `${finalUsername}${randomSuffix}`;
      console.log(`⚠️ Username collision! Auto-generated: ${finalUsername}`);
    }

    // 3. Buat User Baru dengan username yang sudah aman
    console.log(`🆕 [Backend] Creating NEW user: ${email} as ${finalUsername}`);
    const newUser = await prisma.user.create({
      data: {
        id: id,
        email: email,
        username: finalUsername, // Pakai username yang sudah di-cek
        avatarUrl: avatarUrl,
        password: "GOOGLE_OAUTH_USER_DUMMY_PASSWORD", 
        role: "USER",
      },
    });

    res.status(201).json({ message: "User created via Google", user: newUser });

  } catch (error: any) {
    console.error("🔥 [Backend] PRISMA ERROR:", error);
    res.status(500).json({ 
        error: "Gagal sinkronisasi user Google", 
        details: error.message 
    });
  }
});


export default router;