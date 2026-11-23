using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace VaultKeep
{
    /// <summary>
    /// PBKDF2-HMAC-SHA256 using Windows CNG (native, ~4x faster than .NET Framework's managed
    /// Rfc2898DeriveBytes), falling back to Rfc2898DeriveBytes if CNG is unavailable.
    /// Both produce identical output (standard RFC 8018 PBKDF2); tests check this.
    /// </summary>
    internal static class Pbkdf2
    {
        private const int BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;

        public static byte[] DeriveSha256(byte[] password, byte[] salt, int iterations, int length)
        {
            try
            {
                return DeriveNative(password, salt, iterations, length);
            }
            catch (Exception ex)
            {
                if (ex is OutOfMemoryException) throw;
                return DeriveManaged(password, salt, iterations, length);
            }
        }

        public static byte[] DeriveManaged(byte[] password, byte[] salt, int iterations, int length)
        {
            using (var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
                return kdf.GetBytes(length);
        }

        public static byte[] DeriveNative(byte[] password, byte[] salt, int iterations, int length)
        {
            IntPtr alg;
            int status = BCryptOpenAlgorithmProvider(out alg, "SHA256", null, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (status != 0) throw new CryptographicException("BCryptOpenAlgorithmProvider failed: 0x" + status.ToString("X8"));
            try
            {
                byte[] key = new byte[length];
                status = BCryptDeriveKeyPBKDF2(alg, password, password.Length, salt, salt.Length, (ulong)iterations, key, key.Length, 0);
                if (status != 0) throw new CryptographicException("BCryptDeriveKeyPBKDF2 failed: 0x" + status.ToString("X8"));
                return key;
            }
            finally
            {
                BCryptCloseAlgorithmProvider(alg, 0);
            }
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr handle, string algId, string implementation, int flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDeriveKeyPBKDF2(IntPtr prf, byte[] password, int cbPassword, byte[] salt, int cbSalt,
            ulong iterations, byte[] derivedKey, int cbDerivedKey, int flags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr handle, int flags);
    }
}
