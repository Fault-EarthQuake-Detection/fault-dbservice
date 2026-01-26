// Tambahkan ini di baris PERTAMA
import "dotenv/config";

import { isAdmin } from "./middleware/auth"; // Import middleware baru

import express, { Request, Response } from "express";
import prisma from './utils/prisma';

// Import middleware auth
import { authMiddleware, checkRole, supabaseAdmin } from "./middleware/auth";

// --- IMPORT ROUTE BARU KITA ---
import authRoutes from "./routes/auth";

import cors from "cors";

import bcrypt from "bcryptjs";  

import { Stemmer, Tokenizer } from 'sastrawijs';

// Inisialisasi Prisma Client
const app = express();
const PORT = process.env.PORT || 3000;

// --- SETTING LIMIT PAYLOAD (PENTING) ---
// Naikkan limit agar bisa menerima gambar Base64 yang besar
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ limit: "100mb", extended: true }));

app.use(cors({
  credentials: true,
}));

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
app.use("/auth", authRoutes);

// --- API DATA (YANG DILINDUNGI) ---
const apiRouter = express.Router();
apiRouter.use(authMiddleware); // <-- SEMUA /api/* akan dicek tokennya

app.get("/", (req, res) => {
  res.status(200).json({
    status: "OK",
    message: "Fault Detection Server is Running",
    timestamp: new Date(),
  });
});

apiRouter.get("/detections", async (req: Request, res: Response) => {
  try {
    // Cek apakah ada parameter pagination (biasanya dikirim Flutter)
    const page = req.query.page ? parseInt(req.query.page as string) : null;
    const limit = req.query.limit ? parseInt(req.query.limit as string) : 10;

    if (page && page > 0) {
      // --- LOGIKA UNTUK FLUTTER (PAGINATION) ---
      const skip = (page - 1) * limit;

      const [detections, total] = await prisma.$transaction([
        prisma.detectionReport.findMany({
          skip: skip,
          take: limit,
          orderBy: { createdAt: "desc" },
          include: {
            user: { select: { username: true, avatarUrl: true } }, // Include avatar juga buat mobile
          },
        }),
        prisma.detectionReport.count(),
      ]);

      return res.status(200).json({
        data: detections,
        meta: {
          total,
          page,
          last_page: Math.ceil(total / limit),
        },
      });
    }

    // --- LOGIKA LAMA (UNTUK NEXT.JS) - TETAP JALAN SEPERTI BIASA ---
    // Next.js biasanya request tanpa query ?page=...
    const detections = await prisma.detectionReport.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        user: { select: { username: true } },
      },
      // Opsional: Batasi limit default biar server ga berat kalau data ribuan
      take: 100,
    });
    res.status(200).json(detections);
  } catch (error) {
    res.status(500).json({ error: "Gagal mengambil data deteksi." });
  }
});

// --- ENDPOINT POST DETECTIONS (AUTO-SYNC GOOGLE USER) ---
apiRouter.post("/detections", async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    // 1. Ambil data user dari Token Supabase
    const userId = authReq.user?.id;
    const userEmail = authReq.user?.email; // Sekarang ini valid karena interface sudah diperbaiki

    if (!userId || !userEmail) {
      return res
        .status(401)
        .json({ error: "User tidak terotentikasi atau email tidak valid." });
    }

    // --- PERBAIKAN: SINKRONISASI USER OAUTH ---
    // Cek apakah user ini sudah ada di tabel lokal Prisma
    const localUser = await prisma.user.findUnique({
      where: { id: userId },
    });

    // Jika user belum ada (Login Google pertama kali), buatkan di DB lokal
    if (!localUser) {
      try {
        console.log(
          `User Google baru terdeteksi: ${userEmail}. Membuat data lokal...`
        );
        await prisma.user.create({
          data: {
            id: userId, // PENTING: Pakai ID yang sama dengan Supabase
            email: userEmail,
            // Generate username dari email (hapus domain @gmail.com)
            username: userEmail.split("@")[0] + "_" + userId.substring(0, 4),
            // Isi password dummy karena login pakai Google
            password: "GOOGLE_OAUTH_USER_DUMMY_PASSWORD",
            role: "USER",
          },
        });
      } catch (createUserError) {
        console.error("Gagal sinkronisasi user OAuth:", createUserError);
        return res
          .status(500)
          .json({
            error: "Gagal sinkronisasi data user Google ke database lokal.",
          });
      }
    }
    // ------------------------------------------

    const {
      latitude,
      longitude,
      imageUrl,
      originalImageUrl,
      overlayImageUrl,
      maskImageUrl,
      description,
      detectionResult,
    } = req.body;

    // Normalisasi nama field gambar (karena frontend mungkin kirim imageUrl atau originalImageUrl)
    const finalOriginalImage = originalImageUrl || imageUrl;

    if (!latitude || !longitude || !finalOriginalImage) {
      return res
        .status(400)
        .json({ error: "Data lokasi dan gambar asli wajib diisi." });
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
        maskImageUrl: maskImageUrl || "", // Wajib di schema, isi default string kosong

        statusLevel: statusLevel,
        faultType: detectionResult, // detectionResult dari frontend masuk ke faultType di DB
        description: description,

        userId: userId, // Foreign Key ke User
      },
    });

    res.status(201).json(newDetection);
  } catch (error) {
    console.error("Error saving detection:", error);
    res
      .status(500)
      .json({ error: "Gagal menyimpan data deteksi ke database." });
  }
});

apiRouter.delete(
  "/detections/:id",
  checkRole("ADMIN"),
  async (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      await prisma.detectionReport.delete({
        where: { id: parseInt(id) },
      });
      res.status(204).send();
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Gagal menghapus deteksi." });
    }
  }
);

// Pasang /api router
app.use("/api", apiRouter);

// --- Endpoint Admin Sementara ---
app.post("/api/admin/set-role", async (req: Request, res: Response) => {
  try {
    const { user_id, role } = req.body;
    if (!user_id || !role) {
      return res.status(400).json({ error: "user_id dan role wajib diisi" });
    }
    const { data, error } = await supabaseAdmin.auth.admin.updateUserById(
      user_id,
      { app_metadata: { roles: [role] } }
    );
    if (error) throw error;
    res.status(200).json({ message: `User ${user_id} role updated.`, data });
  } catch (error: any) {
    res
      .status(500)
      .json({ error: "Gagal update user role", details: error.message });
  }
});

// --- API: UPDATE PROFILE (Username & Avatar) ---
apiRouter.put("/profile", async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    const userId = authReq.user?.id;
    const userEmail = authReq.user?.email; // Kita butuh email untuk kasus 'create'
    const { username, avatarUrl } = req.body;

    if (!userId || !userEmail) {
      return res
        .status(401)
        .json({ error: "Unauthorized: User ID atau Email tidak ditemukan." });
    }

    // --- PERBAIKAN: Gunakan UPSERT (Update jika ada, Create jika belum) ---
    const updatedUser = await prisma.user.upsert({
      where: { id: userId },
      // 1. Jika user sudah ada, update data ini:
      update: {
        username: username,
        avatarUrl: avatarUrl,
      },
      // 2. Jika user belum ada (User Google baru), buat data baru ini:
      create: {
        id: userId,
        email: userEmail,
        username: username,
        avatarUrl: avatarUrl,
        password: "GOOGLE_OAUTH_USER_DUMMY_PASSWORD", // Password dummy wajib diisi
        role: "USER",
      },
    });

    // 2. Update Metadata di Supabase (Agar sinkron)
    try {
      await supabaseAdmin.auth.admin.updateUserById(userId, {
        user_metadata: { username: username, avatar_url: avatarUrl },
      });
    } catch (metaError) {
      console.warn(
        "Gagal update metadata Supabase (tidak kritikal).",
        metaError
      );
    }

    res.json({ message: "Profil berhasil diperbarui", user: updatedUser });
  } catch (error) {
    console.error("Error update profile:", error);
    res
      .status(500)
      .json({
        error: "Gagal memperbarui profil. Username mungkin sudah digunakan.",
      });
  }
});

// ... (kode import dan inisialisasi lainnya tetap sama) ...

// --- 2. Tambahkan Endpoint ini di bawah endpoint /profile ---

// --- API: GANTI PASSWORD (Sinkron DB Lokal & Supabase) ---
apiRouter.put("/change-password", async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    const userId = authReq.user?.id;
    const { oldPassword, newPassword } = req.body;

    if (!userId) return res.status(401).json({ error: "Unauthorized" });
    if (!oldPassword || !newPassword) {
      return res
        .status(400)
        .json({ error: "Password lama dan baru wajib diisi." });
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ error: "Password baru minimal 6 karakter." });
    }

    // A. Ambil data user dari DB Lokal
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ error: "User tidak ditemukan." });

    // B. Cek apakah user ini login via Google (password dummy)
    // Jika user Google mencoba hit API ini (misal lewat Postman), kita tolak
    if (
      user.password === "GOOGLE_OAUTH_USER_DUMMY_PASSWORD" ||
      user.password === "GOOGLE_OAUTH_USER"
    ) {
      return res
        .status(403)
        .json({ error: "Akun Google tidak dapat mengganti password di sini." });
    }

    // C. Verifikasi Password Lama
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Password lama salah." });
    }

    // D. Hash Password Baru
    const salt = await bcrypt.genSalt(10);
    const newHashedPassword = await bcrypt.hash(newPassword, salt);

    // E. Update di Database Lokal (Prisma)
    await prisma.user.update({
      where: { id: userId },
      data: { password: newHashedPassword },
    });

    // F. Update di Supabase Auth (Admin)
    const { error: supabaseError } =
      await supabaseAdmin.auth.admin.updateUserById(
        userId,
        { password: newPassword } // Supabase butuh plain text, dia akan hash sendiri
      );

    if (supabaseError) {
      // Jika update supabase gagal, kembalikan (rollback) DB lokal?
      // Untuk sederhananya kita log error saja, tapi user harus tau.
      console.error("Gagal update password Supabase:", supabaseError);
      return res
        .status(500)
        .json({ error: "Gagal sinkronisasi password ke sistem Auth." });
    }

    res.json({ message: "Password berhasil diganti. Silakan login ulang." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Terjadi kesalahan server." });
  }
});

// --- API KHUSUS FLUTTER: FORCE SYNC USER ---
// Dipanggil oleh Flutter tepat setelah Login Google berhasil
apiRouter.post("/sync-user", async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    const userId = authReq.user?.id;
    const userEmail = authReq.user?.email;

    if (!userId || !userEmail) {
      return res.status(401).json({ error: "Token tidak valid." });
    }

    // Gunakan UPSERT: Buat jika belum ada, Update jika sudah ada (biar aman)
    const user = await prisma.user.upsert({
      where: { id: userId },
      update: { email: userEmail }, // Update email jaga-jaga kalau berubah
      create: {
        id: userId,
        email: userEmail,
        username:
          userEmail.split("@")[0] + "_" + Math.floor(Math.random() * 1000),
        password: "GOOGLE_OAUTH_USER_FLUTTER", // Penanda user dari Flutter
        role: "USER",
      },
    });

    res.status(200).json({ message: "User synced successfully", user });
  } catch (error) {
    console.error("Sync error:", error);
    res.status(500).json({ error: "Gagal sinkronisasi user." });
  }
});

apiRouter.post("/feedback", async (req: Request, res: Response) => {
  const authReq = req as AuthRequest;
  try {
    const userId = authReq.user?.id;
    const { content } = req.body;

    if (!userId) return res.status(401).json({ error: "Unauthorized" });
    if (!content)
      return res.status(400).json({ error: "Isi saran tidak boleh kosong." });

    await prisma.feedback.create({
      data: {
        content: content,
        userId: userId,
      },
    });

    res.status(201).json({ message: "Terima kasih atas saran Anda!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Gagal mengirim saran." });
  }
});

// src/index.ts

// ... (Kode setup express lainnya)

// --- ADMIN ROUTES ---

// 1. GET Semua Deteksi (Termasuk yang belum valid)
app.get(
  "/api/admin/detections",
  authMiddleware,
  isAdmin,
  async (req: Request, res: Response) => {
    try {
      const reports = await prisma.detectionReport.findMany({
        orderBy: { createdAt: "desc" },
        include: {
          user: { select: { username: true, email: true } }, // Include info uploader
        },
      });
      res.json(reports);
    } catch (e) {
      res.status(500).json({ error: "Failed to fetch reports" });
    }
  }
);

// 2. PUT Validasi Deteksi (Terima/Tolak)
app.put(
  "/api/admin/detections/:id/validate",
  authMiddleware,
  isAdmin,
  async (req, res) => {
    const authReq = req as AuthRequest;
    const { id } = req.params;
    const { isValid } = req.body; // true atau false

    try {
      const updated = await prisma.detectionReport.update({
        where: { id: Number(id) },
        data: {
          isValidated: isValid,
          validatedAt: new Date(),
          validatedBy: authReq.user?.id,
        },
      });
      res.json(updated);
    } catch (e) {
      res.status(500).json({ error: "Failed to validate" });
    }
  }
);
// 3. DELETE Deteksi (Hapus Laporan Ngawur)
app.delete(
  "/api/admin/detections/:id",
  authMiddleware,
  isAdmin,
  async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
      await prisma.detectionReport.delete({
        where: { id: Number(id) },
      });
      res.json({ message: "Report deleted successfully" });
    } catch (e) {
      res.status(500).json({ error: "Failed to delete" });
    }
  }
);

// 4. GET Semua User (Untuk Ganti Role)
app.get(
  "/api/admin/users",
  authMiddleware,
  isAdmin,
  async (req: Request, res: Response) => {
    try {
      const users = await prisma.user.findMany({
        orderBy: { createdAt: "desc" },
        select: {
          id: true,
          username: true,
          email: true,
          role: true,
          avatarUrl: true,
        },
      });
      res.json(users);
    } catch (e) {
      res.status(500).json({ error: "Failed to fetch users" });
    }
  }
);

// 5. PUT Ganti Role User
app.put(
  "/api/admin/users/:id/role",
  authMiddleware,
  isAdmin,
  async (req: Request, res: Response) => {
    const { id } = req.params;
    const { role } = req.body; // "ADMIN" atau "USER"

    try {
      const updated = await prisma.user.update({
        where: { id: String(id) },
        data: { role: role },
      });
      res.json(updated);
    } catch (e) {
      res.status(500).json({ error: "Failed to update role" });
    }
  }
);

// src/index.ts

// ... (kode sebelumnya)

// --- TAMBAHAN: Endpoint untuk Cek Profile & Role Asli ---
// Frontend akan memanggil ini untuk memastikan apakah dia ADMIN atau USER
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const authReq = req as AuthRequest;
    const userId = authReq.user?.id;
    
    // Ambil data fresh dari tabel Prisma
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { 
        id: true, 
        username: true, 
        email: true, 
        role: true, // INI KUNCINYA
        avatarUrl: true 
      }
    });

    if (!user) {
      return res.status(404).json({ error: "User not found in DB" });
    }

    res.json(user);
  } catch (error) {
    console.error("Me Endpoint Error:", error);
    res.status(500).json({ error: "Server Error" });
  }
});

// --- 6. GET Feedback dengan Sentiment Analysis (ADMIN) ---
// --- ROUTE FEEDBACK ANALYTICS (ADMIN) ---
app.get(
  "/api/admin/feedbacks-analytics",
  authMiddleware,
  isAdmin,
  async (req: Request, res: Response) => {
    try {
      // --- 1. PERSIAPAN ALAT NLP ---
      const stemmer = new Stemmer();
      const tokenizer = new Tokenizer();

      // Dictionary Kata Dasar (Root Words) & Bobotnya
      // Perhatikan: Gunakan kata dasar saja (bantu, bukan membantu) karena kita akan stemming dulu.
      const lexicon: Record<string, number> = {
        // POSITIF
        'bagus': 3, 'keren': 4, 'mantap': 4, 'hebat': 4, 'puas': 3, 
        'suka': 3, 'baik': 3, 'manfaat': 4, 'bantu': 3, 'cepat': 3, 
        'aman': 3, 'mudah': 3, 'nyaman': 3, 'oke': 2, 'lancar': 3, 
        'jelas': 3, 'rapi': 3, 'senang': 3, 'kasih': 2, 'terima': 2, // untuk terima kasih
        'top': 4, 'gacor': 5, 'valid': 4, 'akurat': 4,
        
        // NEGATIF
        'jelek': -3, 'buruk': -4, 'rusak': -5, 'kecewa': -4, 
        'lambat': -3, 'susah': -3, 'sulit': -3, 'ribet': -3, 'gagal': -4, 
        'parah': -4, 'benci': -5, 'lelet': -3, 'lemot': -3, 
        'bug': -2, 'error': -2, 'ganggu': -3, 'mahal': -3, 
        'kasar': -4, 'kotor': -3, 'sampah': -5, 'bodoh': -4, 
        'tolol': -5, 'tidak': -2, 'jangan': -2, 'kurang': -2
      };

      // Stopwords (Kata yang diabaikan/Filtering)
      const stopWords = [
        "yang", "di", "ke", "dari", "dan", "atau", "ini", "itu", "juga",
        "saya", "aku", "kamu", "dia", "mereka", "kita", "adalah", "pada",
        "dengan", "bisa", "akan", "sudah", "lagi", "ada"
      ];

      // --- 2. AMBIL DATA DARI DB ---
      const feedbacks = await prisma.feedback.findMany({
        orderBy: { createdAt: "desc" },
        include: {
          user: { select: { username: true, email: true, avatarUrl: true } },
        },
      });

      // --- 3. PROSES NLP ---
      let positiveCount = 0;
      let negativeCount = 0;
      let neutralCount = 0;

      const analyzedFeedbacks = feedbacks.map((item: any) => {
        const text = item.content || "";

        // A. CASEFOLDING
        const casefolded = text.toLowerCase();

        // B. TOKENIZING (Hapus simbol & pecah jadi array)
        const cleanText = casefolded.replace(/[^a-z0-9\s-]/g, ''); 
        const tokens = tokenizer.tokenize(cleanText);

        // C. FILTERING (Stopword Removal)
        const filtered = tokens.filter((word: string) => !stopWords.includes(word));

        // D. STEMMING (Mengubah ke kata dasar)
        // Kita stem satu per satu kata yang tersisa
        const stemmedWords = filtered.map((word: string) => stemmer.stem(word));

        // E. SCORING (Evaluation)
        let score = 0;
        stemmedWords.forEach((word: string) => {
          if (lexicon[word]) {
            score += lexicon[word];
          }
        });

        // Tentukan Label
        let sentimentLabel = "Netral";
        if (score > 0) {
          sentimentLabel = "Positif";
          positiveCount++;
        } else if (score < 0) {
          sentimentLabel = "Negatif";
          negativeCount++;
        } else {
          neutralCount++;
        }

        return {
          ...item,
          sentimentScore: score,
          sentimentLabel: sentimentLabel,
          // Opsional: Balikin hasil preprocessing buat bukti ke dosen
          nlpSteps: {
            tokens: tokens,
            filtered: filtered,
            stemmed: stemmedWords
          }
        };
      });

      // --- 4. RETURN RESPONSE ---
      res.json({
        feedbacks: analyzedFeedbacks,
        summary: [
          { name: 'Positif', value: positiveCount, fill: '#22c55e' },
          { name: 'Netral', value: neutralCount, fill: '#94a3b8' },
          { name: 'Negatif', value: negativeCount, fill: '#ef4444' },
        ]
      });

    } catch (e) {
      console.error(e);
      res.status(500).json({ error: "Gagal memuat analisis feedback" });
    }
  }
);
// ... (sisa kode routes admin dll)

// --- Menjalankan Server ---
app.listen(PORT, () => {
  console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
});
