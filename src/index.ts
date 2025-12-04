// Tambahkan ini di baris PERTAMA
import 'dotenv/config';

import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

// Import middleware auth
import { authMiddleware, checkRole, supabaseAdmin } from './middleware/auth';

// --- IMPORT ROUTE BARU KITA ---
import authRoutes from './routes/auth';

import cors from 'cors';

import bcrypt from 'bcryptjs'; 

// Inisialisasi Prisma Client
const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;

// --- SETTING LIMIT PAYLOAD (PENTING) ---
// Naikkan limit agar bisa menerima gambar Base64 yang besar
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

app.use(cors({ origin: 'http://localhost:3001' }));

// --- PERBAIKAN INTERFACE (CRITICAL FIX) ---
// Menambahkan properti 'email' agar tidak error saat diakses
interface AuthRequest extends Request {
  user?: { 
    id: string; 
    email?: string; 
    app_metadata?: any;
    user_metadata?: any;
    aud?: string;
    created_at?: string;
  };
}

// --- PASANG ROUTE AUTH KITA ---
app.use('/auth', authRoutes);


// --- API DATA (YANG DILINDUNGI) ---
const apiRouter = express.Router();
apiRouter.use(authMiddleware); // <-- SEMUA /api/* akan dicek tokennya

apiRouter.get('/detections', async (req: Request, res: Response) => {
  try {
    const detections = await prisma.detectionReport.findMany({
      orderBy: { createdAt: 'desc' },
      include: {
        user: { select: { username: true } },
      },
    });
    res.status(200).json(detections);
  } catch (error) {
    res.status(500).json({ error: 'Gagal mengambil data deteksi.' });
  }
});

// --- ENDPOINT POST DETECTIONS (AUTO-SYNC GOOGLE USER) ---
apiRouter.post('/detections', async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    // 1. Ambil data user dari Token Supabase
    const userId = authReq.user?.id;
    const userEmail = authReq.user?.email; // Sekarang ini valid karena interface sudah diperbaiki

    if (!userId || !userEmail) {
      return res.status(401).json({ error: 'User tidak terotentikasi atau email tidak valid.' });
    }

    // --- PERBAIKAN: SINKRONISASI USER OAUTH ---
    // Cek apakah user ini sudah ada di tabel lokal Prisma
    const localUser = await prisma.user.findUnique({
      where: { id: userId },
    });

    // Jika user belum ada (Login Google pertama kali), buatkan di DB lokal
    if (!localUser) {
      try {
        console.log(`User Google baru terdeteksi: ${userEmail}. Membuat data lokal...`);
        await prisma.user.create({
          data: {
            id: userId, // PENTING: Pakai ID yang sama dengan Supabase
            email: userEmail,
            // Generate username dari email (hapus domain @gmail.com)
            username: userEmail.split('@')[0] + '_' + userId.substring(0, 4),
            // Isi password dummy karena login pakai Google
            password: 'GOOGLE_OAUTH_USER_DUMMY_PASSWORD', 
            role: 'USER',
          },
        });
      } catch (createUserError) {
        console.error("Gagal sinkronisasi user OAuth:", createUserError);
        return res.status(500).json({ error: 'Gagal sinkronisasi data user Google ke database lokal.' });
      }
    }
    // ------------------------------------------

    const { 
      latitude, 
      longitude, 
      imageUrl, 
      originalImageUrl,
      overlayImageUrl,
      description, 
      detectionResult 
    } = req.body;

    // Normalisasi nama field gambar (karena frontend mungkin kirim imageUrl atau originalImageUrl)
    const finalOriginalImage = originalImageUrl || imageUrl;

    if (!latitude || !longitude || !finalOriginalImage) {
      return res.status(400).json({ error: 'Data lokasi dan gambar asli wajib diisi.' });
    }

    // Ekstrak statusLevel dari description JSON jika ada
    let statusLevel = "INFO";
    try {
      if (description) {
        const descJson = JSON.parse(description);
        if (descJson.visual_status) statusLevel = descJson.visual_status;
      }
    } catch (e) {
      // Ignore json parse error
    }

    // Simpan Laporan ke Database
    const newDetection = await prisma.detectionReport.create({
      data: {
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        
        // Mapping field
        originalImageUrl: finalOriginalImage,
        overlayImageUrl: overlayImageUrl || "", // Jika tidak ada overlay, isi string kosong
        maskImageUrl: "", // Wajib di schema, isi default string kosong
        
        statusLevel: statusLevel,
        faultType: detectionResult, // detectionResult dari frontend masuk ke faultType di DB
        description: description,
        
        userId: userId, // Foreign Key ke User
      },
    });
    
    res.status(201).json(newDetection);

  } catch (error) {
    console.error("Error saving detection:", error);
    res.status(500).json({ error: 'Gagal menyimpan data deteksi ke database.' });
  }
});

apiRouter.delete('/detections/:id', checkRole('ADMIN'), async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    await prisma.detectionReport.delete({
      where: { id: parseInt(id) },
    });
    res.status(204).send();
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Gagal menghapus deteksi.' });
  }
});

// Pasang /api router
app.use('/api', apiRouter);


// --- Endpoint Admin Sementara ---
app.post('/api/admin/set-role', async (req: Request, res: Response) => {
  try {
    const { user_id, role } = req.body;
    if (!user_id || !role) {
      return res.status(400).json({ error: 'user_id dan role wajib diisi' });
    }
    const { data, error } = await supabaseAdmin.auth.admin.updateUserById(
      user_id,
      { app_metadata: { roles: [role] } }
    );
    if (error) throw error;
    res.status(200).json({ message: `User ${user_id} role updated.`, data });
  } catch (error: any) {
    res.status(500).json({ error: 'Gagal update user role', details: error.message });
  }
});

// --- API: UPDATE PROFILE (Username & Avatar) ---
// --- API: UPDATE PROFILE (Username & Avatar) ---
// --- API: UPDATE PROFILE (Username & Avatar) ---
apiRouter.put('/profile', async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    const userId = authReq.user?.id;
    const userEmail = authReq.user?.email; // Kita butuh email untuk kasus 'create'
    const { username, avatarUrl } = req.body;

    if (!userId || !userEmail) {
      return res.status(401).json({ error: 'Unauthorized: User ID atau Email tidak ditemukan.' });
    }

    // --- PERBAIKAN: Gunakan UPSERT (Update jika ada, Create jika belum) ---
    const updatedUser = await prisma.user.upsert({
      where: { id: userId },
      // 1. Jika user sudah ada, update data ini:
      update: { 
        username: username,
        avatarUrl: avatarUrl 
      },
      // 2. Jika user belum ada (User Google baru), buat data baru ini:
      create: {
        id: userId,
        email: userEmail,
        username: username,
        avatarUrl: avatarUrl,
        password: 'GOOGLE_OAUTH_USER_DUMMY_PASSWORD', // Password dummy wajib diisi
        role: 'USER'
      }
    });

    // 2. Update Metadata di Supabase (Agar sinkron)
    try {
      await supabaseAdmin.auth.admin.updateUserById(userId, {
        user_metadata: { username: username, avatar_url: avatarUrl }
      });
    } catch (metaError) {
      console.warn("Gagal update metadata Supabase (tidak kritikal).", metaError);
    }

    res.json({ message: 'Profil berhasil diperbarui', user: updatedUser });
  } catch (error) {
    console.error("Error update profile:", error);
    res.status(500).json({ error: 'Gagal memperbarui profil. Username mungkin sudah digunakan.' });
  }
});

// ... (kode import dan inisialisasi lainnya tetap sama) ...

// --- 2. Tambahkan Endpoint ini di bawah endpoint /profile ---

// --- API: GANTI PASSWORD (Sinkron DB Lokal & Supabase) ---
apiRouter.put('/change-password', async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    const userId = authReq.user?.id;
    const { oldPassword, newPassword } = req.body;

    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Password lama dan baru wajib diisi.' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password baru minimal 6 karakter.' });
    }

    // A. Ambil data user dari DB Lokal
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: 'User tidak ditemukan.' });

    // B. Cek apakah user ini login via Google (password dummy)
    // Jika user Google mencoba hit API ini (misal lewat Postman), kita tolak
    if (user.password === 'GOOGLE_OAUTH_USER_DUMMY_PASSWORD' || user.password === 'GOOGLE_OAUTH_USER') {
      return res.status(403).json({ error: 'Akun Google tidak dapat mengganti password di sini.' });
    }

    // C. Verifikasi Password Lama
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Password lama salah.' });
    }

    // D. Hash Password Baru
    const salt = await bcrypt.genSalt(10);
    const newHashedPassword = await bcrypt.hash(newPassword, salt);

    // E. Update di Database Lokal (Prisma)
    await prisma.user.update({
      where: { id: userId },
      data: { password: newHashedPassword }
    });

    // F. Update di Supabase Auth (Admin)
    const { error: supabaseError } = await supabaseAdmin.auth.admin.updateUserById(
      userId,
      { password: newPassword } // Supabase butuh plain text, dia akan hash sendiri
    );

    if (supabaseError) {
      // Jika update supabase gagal, kembalikan (rollback) DB lokal? 
      // Untuk sederhananya kita log error saja, tapi user harus tau.
      console.error("Gagal update password Supabase:", supabaseError);
      return res.status(500).json({ error: 'Gagal sinkronisasi password ke sistem Auth.' });
    }

    res.json({ message: 'Password berhasil diganti. Silakan login ulang.' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Terjadi kesalahan server.' });
  }
});

apiRouter.post('/feedback', async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    const userId = authReq.user?.id;
    const { content } = req.body;

    if (!userId) return res.status(401).json({ error: 'Unauthorized' });
    if (!content) return res.status(400).json({ error: 'Isi saran tidak boleh kosong.' });

    await prisma.feedback.create({
      data: {
        content: content,
        userId: userId
      }
    });

    res.status(201).json({ message: 'Terima kasih atas saran Anda!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Gagal mengirim saran.' });
  }
});

// --- Menjalankan Server ---
app.listen(PORT, () => {
  console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
});