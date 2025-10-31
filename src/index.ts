// Tambahkan ini di baris PERTAMA
import 'dotenv/config';

import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

// Import middleware auth yang sudah kita buat
import { authMiddleware, checkRole } from './middleware/auth';

// Inisialisasi Prisma Client
const prisma = new PrismaClient();

// Inisialisasi aplikasi Express
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware untuk membaca JSON body dari request
app.use(express.json());

// --- Tipe Bantuan untuk Request ---
// Ini agar TypeScript tahu ada 'req.user' setelah authMiddleware
interface AuthRequest extends Request {
  user?: {
    id: string; // ID user dari Supabase (ini adalah string UUID)
    // ... properti lain dari user jika perlu
  };
}

// --- DEFINISI ENDPOINT API ---

/**
 * GET /
 * Rute sapaan atau health check
 */
app.get('/', (req: Request, res: Response) => {
  res.status(200).json({ message: 'Selamat datang di Fault Detection API' });
});

/**
 * GET /api/detections
 * Dilindungi: Hanya user yang sudah login bisa melihat.
 */
app.get('/api/detections', authMiddleware, async (req: Request, res: Response) => {
  try {
    const detections = await prisma.detectionReport.findMany({
      orderBy: {
        createdAt: 'desc', // Tampilkan dari yang terbaru
      },
      include: {
        // Sertakan data user yang mem-posting (opsional tapi bagus)
        user: {
          select: {
            username: true, // Asumsi Anda punya field 'username' di tabel User
          },
        },
      },
    });
    res.status(200).json(detections);
  } catch (error) {
    res.status(500).json({ error: 'Gagal mengambil data deteksi.' });
  }
});

/**
 * POST /api/detections
 * Dilindungi: Hanya user yang sudah login bisa membuat.
 * ID User diambil dari TOKEN, bukan body.
 */
app.post('/api/detections', authMiddleware, async (req: Request, res: Response) => {
  // 'req' di-cast ke AuthRequest agar kita bisa akses req.user
  const authReq = req as AuthRequest;

  try {
    // Ambil ID user dari middleware (token), BUKAN DARI BODY
    const userId = authReq.user?.id;

    if (!userId) {
      // Ini seharusnya tidak terjadi jika authMiddleware bekerja
      return res.status(401).json({ error: 'User tidak terotentikasi.' });
    }

    // Ambil data dari body (TANPA userId)
    const { latitude, longitude, imageUrl, description, detectionResult } = req.body;

    // Validasi input
    if (!latitude || !longitude || !imageUrl || !detectionResult) {
      return res.status(400).json({ error: 'Field latitude, longitude, imageUrl, dan detectionResult wajib diisi.' });
    }

    const newDetection = await prisma.detectionReport.create({
      data: {
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        imageUrl,
        description,
        detectionResult,
        userId: userId, // <-- ID user (string UUID) diambil dari token yang valid
      },
    });

    res.status(201).json(newDetection);
  } catch (error) {
    console.error(error); // Log error untuk debugging
    res.status(500).json({ error: 'Gagal menyimpan data deteksi.' });
  }
});

/**
 * DELETE /api/detections/:id
 * Dilindungi Ganda: Hanya user login DAN punya role 'ADMIN'.
 */
app.delete('/api/detections/:id', authMiddleware, checkRole('ADMIN'), async (req: Request, res: Response) => {
  // Hanya admin yang bisa sampai ke kode ini
  try {
    const { id } = req.params;
    await prisma.detectionReport.delete({
      where: { id: parseInt(id) }, // Asumsi ID deteksi adalah integer
    });
    res.status(204).send(); // No Content
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Gagal menghapus deteksi.' });
  }
});

// --- Menjalankan Server ---

app.listen(PORT, () => {
  console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
});