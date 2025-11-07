import { createClient } from '@supabase/supabase-js';
import { Request, Response, NextFunction } from 'express';

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