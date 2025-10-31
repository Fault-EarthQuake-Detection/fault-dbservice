import { createClient } from '@supabase/supabase-js';
import { Request, Response, NextFunction } from 'express';

// Tipe kustom untuk menambahkan 'user' ke objek Request Express
interface AuthRequest extends Request {
  user?: any;
}

// Inisialisasi Supabase client (cukup pakai URL dan Anon Key)
const supabaseUrl = process.env.SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!; // Ambil dari .env
const supabase = createClient(supabaseUrl, supabaseAnonKey);

/**
 * Middleware untuk memverifikasi token JWT dari Supabase.
 * Ini akan mengecek header 'Authorization: Bearer <TOKEN>'
 */
export const authMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Akses ditolak: Tidak ada token.' });
  }

  const token = authHeader.split(' ')[1];

  // Verifikasi token ke Supabase
  const { data: { user }, error } = await supabase.auth.getUser(token);

  if (error || !user) {
    return res.status(401).json({ error: 'Akses ditolak: Token tidak valid.' });
  }

  // Jika token valid, simpan data user di request untuk dipakai endpoint lain
  req.user = user;
  next(); // Lanjut ke handler berikutnya (atau middleware role)
};

/**
 * Middleware untuk mengecek role user.
 * HARUS dijalankan SETELAH authMiddleware.
 */
export const checkRole = (requiredRole: string) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Autentikasi diperlukan.' });
    }

    // Ambil roles dari metadata user di Supabase
    const userRoles = req.user.app_metadata?.roles || [];

    if (!userRoles.includes(requiredRole)) {
      return res.status(403).json({ error: 'Akses ditolak: Role tidak memadai.' });
    }

    next(); // Role sesuai, lanjut
  };
};