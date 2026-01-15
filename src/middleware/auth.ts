// src/middleware/auth.ts

import { createClient } from '@supabase/supabase-js';
import { Request, Response, NextFunction } from 'express';

import prisma from '../utils/prisma';

// Tipe kustom untuk menambahkan 'user' ke objek Request Express
interface AuthRequest extends Request {
  user?: any;
}

// --- PERUBAHAN DI SINI ---
// Kita pakai Service Role Key (Kunci Master)
const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY!;

// Kita inisialisasi sebagai Admin Client dan EXPORT
export const supabaseAdmin = createClient(supabaseUrl, supabaseServiceKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

/**
 * Middleware untuk memverifikasi token JWT dari Supabase.
 */
export const authMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Akses ditolak: Tidak ada token.' });
  }

  const token = authHeader.split(' ')[1];

  // --- PERUBAHAN DI SINI ---
  // Verifikasi token pakai Admin Client (supabaseAdmin)
  const { data: { user }, error } = await supabaseAdmin.auth.getUser(token);

  if (error || !user) {
    return res.status(401).json({ error: 'Akses ditolak: Token tidak valid.' });
  }

  // Jika token valid, simpan data user di request
  req.user = user;
  next(); // Lanjut
};

/**
 * Middleware untuk mengecek role user.
 */
export const checkRole = (requiredRole: string) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Autentikasi diperlukan.' });
    }

    // Ambil roles dari metadata user di Supabase
    // Ini sekarang akan berhasil karena kita pakai Service Key
    const userRoles = req.user.app_metadata?.roles || [];

    if (!userRoles.includes(requiredRole)) {
      return res.status(403).json({ error: 'Akses ditolak: Role tidak memadai.' });
    }

    next(); // Role sesuai, lanjut
  };
};

// src/middleware/auth.ts

// Middleware Check Admin
export const isAdmin = async (req: any, res: Response, next: NextFunction) => {
  try {
    // req.user sudah diisi oleh authMiddleware sebelumnya
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: "Unauthorized: No User ID" });
    }

    // Cek Role di Database Lokal
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { role: true }
    });

    if (user?.role !== 'ADMIN') {
      return res.status(403).json({ error: "Forbidden: Admin access required" });
    }

    next();
  } catch (error) {
    console.error("Admin Check Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};