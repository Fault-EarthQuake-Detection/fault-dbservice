// Tambahkan ini di baris PERTAMA
import 'dotenv/config';

import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

// Import middleware auth
import { authMiddleware, checkRole, supabaseAdmin } from './middleware/auth';

// --- IMPORT ROUTE BARU KITA ---
import authRoutes from './routes/auth';

import cors from 'cors';

// Inisialisasi Prisma Client
const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use(cors({ origin: 'http://localhost:3001' }));

// --- Tipe Bantuan (biarkan saja) ---
interface AuthRequest extends Request {
  user?: { id: string; };
}

// --- PASANG ROUTE AUTH KITA ---
// Semua rute di /auth (signup, login, magic-link) akan di-handle di sini
app.use('/auth', authRoutes);


// --- API DATA (YANG DILINDUNGI) ---
// Rute ini tetap sama, dijaga oleh authMiddleware
const apiRouter = express.Router();
apiRouter.use(authMiddleware); // <-- SEMUA /api/* akan dicek tokennya

apiRouter.get('/detections', async (req: Request, res: Response) => {
  // ... (kode lo untuk get detections)
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

apiRouter.post('/detections', async (req: Request, res: Response) => {
  // ... (kode lo untuk post detections)
  const authReq = req as AuthRequest;
  try {
    const userId = authReq.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'User tidak terotentikasi.' });
    }
    const { latitude, longitude, imageUrl, description, detectionResult } = req.body;
    if (!latitude || !longitude || !imageUrl || !detectionResult) {
      return res.status(400).json({ error: 'Field latitude, longitude, imageUrl, dan detectionResult wajib diisi.' });
    }
    const newDetection = await prisma.detectionReport.create({
      data: {
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        originalImageUrl: imageUrl,
        description,
        detectionResult,
        userId: userId,
      },
    });
    res.status(201).json(newDetection);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Gagal menyimpan data deteksi.' });
  }
});

apiRouter.delete('/detections/:id', checkRole('ADMIN'), async (req: Request, res: Response) => {
  // ... (kode lo untuk delete detections)
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


// --- Endpoint Admin Sementara (biarkan saja untuk debug) ---
app.post('/api/admin/set-role', async (req: Request, res: Response) => {
  // ... (kode endpoint set-role lo)
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

// --- Menjalankan Server ---
app.listen(PORT, () => {
  console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
});