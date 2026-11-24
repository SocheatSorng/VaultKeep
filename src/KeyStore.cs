using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VaultKeep
{
    /// <summary>
    /// Where VaultKeep keeps its per-user data. Only the test build (TESTHOOKS) lets VAULTKEEP_HOME redirect it:
    /// in the real app, an environment variable must not be able to swap in someone else's key list.
    /// </summary>
    internal static class AppPaths
    {
        public static string DataDir
        {
            get
            {
#if TESTHOOKS
                string over = Environment.GetEnvironmentVariable("VAULTKEEP_HOME");
                if (!string.IsNullOrEmpty(over)) return over;
#endif
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VaultKeep");
            }
        }
    }

    /// <summary>A key registered on this PC: only the public half, used to add a key slot when locking.</summary>
    internal sealed class RegisteredKey
    {
        public byte[] Id;
        public string Label;
        public DateTime CreatedUtc;
        public RSAParameters PublicKey;

        public string IdHex { get { return KeyStore.ToHex(Id); } }
    }

    /// <summary>A key found on a plugged-in drive: holds the private half, used to open items.</summary>
    internal sealed class KeyFile
    {
        public byte[] Id;
        public string Label;
        public string Path;
        public RSAParameters PrivateKey;

        public string IdHex { get { return KeyStore.ToHex(Id); } }
    }

    /// <summary>
    /// USB security keys. A key is an RSA-3072 key pair:
    ///   - private key: in "&lt;drive&gt;:\.vaultkeep\vaultkeep.vkkey" on the flash drive (whoever has the
    ///     drive has the key, so keep it safe like a house key);
    ///   - public key: registered on this PC in keys.dat (DPAPI-encrypted), so items can be locked for the
    ///     key even when the drive is not plugged in.
    /// </summary>
    internal static class KeyStore
    {
        public const string KeyFolderName = ".vaultkeep";
        public const string KeyFileName = "vaultkeep.vkkey";
        private const int RsaBits = 3072;
        private static readonly byte[] KeyMagic = Encoding.ASCII.GetBytes("VKKEY1");
        private static readonly byte[] StoreMagic = Encoding.ASCII.GetBytes("VKKS1");
        private static readonly byte[] Entropy = Encoding.ASCII.GetBytes("VaultKeep keys v1");

        private static string StorePath { get { return Path.Combine(AppPaths.DataDir, "keys.dat"); } }

        public static string KeyFilePath(string root)
        {
            return Path.Combine(Path.Combine(root, KeyFolderName), KeyFileName);
        }

        // ------------------------------------------------------------ Registry

        public static List<RegisteredKey> LoadRegistered()
        {
            var list = new List<RegisteredKey>();
            if (!File.Exists(StorePath)) return list;
            byte[] plain = ProtectedData.Unprotect(File.ReadAllBytes(StorePath), Entropy, DataProtectionScope.CurrentUser);
            using (var r = new BinaryReader(new MemoryStream(plain), Encoding.UTF8))
            {
                byte[] magic = r.ReadBytes(StoreMagic.Length);
                if (!BytesEqual(magic, StoreMagic)) throw new InvalidDataException("VaultKeep key list is damaged.");
                int count = r.ReadInt32();
                for (int i = 0; i < count; i++)
                {
                    var k = new RegisteredKey();
                    k.Id = r.ReadBytes(16);
                    k.Label = r.ReadString();
                    k.CreatedUtc = new DateTime(r.ReadInt64(), DateTimeKind.Utc);
                    k.PublicKey = new RSAParameters { Modulus = ReadBlob(r), Exponent = ReadBlob(r) };
                    list.Add(k);
                }
            }
            return list;
        }

        private static void SaveRegistered(List<RegisteredKey> keys)
        {
            var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8))
            {
                w.Write(StoreMagic);
                w.Write(keys.Count);
                foreach (RegisteredKey k in keys)
                {
                    w.Write(k.Id);
                    w.Write(k.Label ?? "");
                    w.Write(k.CreatedUtc.Ticks);
                    WriteBlob(w, k.PublicKey.Modulus);
                    WriteBlob(w, k.PublicKey.Exponent);
                }
            }
            Directory.CreateDirectory(AppPaths.DataDir);
            byte[] data = ProtectedData.Protect(ms.ToArray(), Entropy, DataProtectionScope.CurrentUser);
            string temp = StorePath + ".tmp";
            File.WriteAllBytes(temp, data);
            if (File.Exists(StorePath)) File.Replace(temp, StorePath, null, true);
            else File.Move(temp, StorePath);
        }

        /// <summary>Registers (the public half of) a key found on a drive. Returns false if already registered.</summary>
        public static bool Register(KeyFile key)
        {
            List<RegisteredKey> keys = LoadRegistered();
            foreach (RegisteredKey k in keys)
                if (BytesEqual(k.Id, key.Id)) return false;
            keys.Add(new RegisteredKey
            {
                Id = key.Id,
                Label = key.Label,
                CreatedUtc = DateTime.UtcNow,
                PublicKey = new RSAParameters { Modulus = key.PrivateKey.Modulus, Exponent = key.PrivateKey.Exponent }
            });
            SaveRegistered(keys);
            return true;
        }

        public static bool Unregister(byte[] id)
        {
            List<RegisteredKey> keys = LoadRegistered();
            int removed = keys.RemoveAll(k => BytesEqual(k.Id, id));
            if (removed > 0) SaveRegistered(keys);
            return removed > 0;
        }

        // ------------------------------------------------------------ Key files

        /// <summary>Creates a new key on the drive/folder <paramref name="root"/> and registers it.</summary>
        public static KeyFile CreateKey(string root, string label)
        {
            string path = KeyFilePath(root);
            if (File.Exists(path))
                throw new IOException("This drive already holds a VaultKeep key.");

            var key = new KeyFile { Id = RandomBytes(16), Label = label, Path = path };
            using (var rsa = new RSACng(RsaBits))
                key.PrivateKey = rsa.ExportParameters(true);

            var dir = Directory.CreateDirectory(Path.GetDirectoryName(path));
            dir.Attributes |= FileAttributes.Hidden;
            var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8))
            {
                w.Write(KeyMagic);
                w.Write(key.Id);
                w.Write(label ?? "");
                RSAParameters p = key.PrivateKey;
                foreach (byte[] part in new[] { p.Modulus, p.Exponent, p.D, p.P, p.Q, p.DP, p.DQ, p.InverseQ })
                    WriteBlob(w, part);
            }
            string temp = path + ".tmp";
            File.WriteAllBytes(temp, ms.ToArray());
            File.Move(temp, path);

            // Prove the written key reads back before telling anyone it exists.
            KeyFile check = ReadKeyFile(path);
            if (check == null || !BytesEqual(check.Id, key.Id))
                throw new IOException("Couldn't write the key to this drive.");

            Register(key);
            return key;
        }

        /// <summary>Reads a key file; returns null if it isn't a valid VaultKeep key.</summary>
        public static KeyFile ReadKeyFile(string path)
        {
            try
            {
                byte[] data = File.ReadAllBytes(path);
                using (var r = new BinaryReader(new MemoryStream(data), Encoding.UTF8))
                {
                    if (!BytesEqual(r.ReadBytes(KeyMagic.Length), KeyMagic)) return null;
                    var key = new KeyFile { Id = r.ReadBytes(16), Label = r.ReadString(), Path = path };
                    var p = new RSAParameters
                    {
                        Modulus = ReadBlob(r), Exponent = ReadBlob(r), D = ReadBlob(r), P = ReadBlob(r),
                        Q = ReadBlob(r), DP = ReadBlob(r), DQ = ReadBlob(r), InverseQ = ReadBlob(r)
                    };
                    using (var rsa = new RSACng()) rsa.ImportParameters(p); // validates the key
                    key.PrivateKey = p;
                    return key;
                }
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Finds VaultKeep keys on plugged-in drives (removable and non-system fixed drives, which covers
        /// USB flash drives and USB hard disks), plus any <paramref name="extraRoots"/> (tests).
        /// </summary>
        public static List<KeyFile> FindKeyFiles(IEnumerable<string> extraRoots, bool scanDrives)
        {
            var roots = new List<string>();
            if (scanDrives)
            {
                string systemDrive = Path.GetPathRoot(Environment.SystemDirectory);
                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (d.DriveType != DriveType.Removable && d.DriveType != DriveType.Fixed) continue;
                        if (d.Name.Equals(systemDrive, StringComparison.OrdinalIgnoreCase)) continue;
                        if (d.IsReady) roots.Add(d.RootDirectory.FullName);
                    }
                    catch { }
                }
            }
            if (extraRoots != null) roots.AddRange(extraRoots);

            var found = new List<KeyFile>();
            foreach (string root in roots)
            {
                string path = KeyFilePath(root);
                if (!File.Exists(path)) continue;
                KeyFile key = ReadKeyFile(path);
                if (key != null) found.Add(key);
            }
            return found;
        }

        /// <summary>Drives a key can be created on (same rules as <see cref="FindKeyFiles"/>).</summary>
        public static List<DriveInfo> CandidateDrives()
        {
            var list = new List<DriveInfo>();
            string systemDrive = Path.GetPathRoot(Environment.SystemDirectory);
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                try
                {
                    if ((d.DriveType == DriveType.Removable || d.DriveType == DriveType.Fixed) && d.IsReady &&
                        !d.Name.Equals(systemDrive, StringComparison.OrdinalIgnoreCase))
                        list.Add(d);
                }
                catch { }
            }
            return list;
        }

        // ---------------------------------------------------------------- Helpers

        private static void WriteBlob(BinaryWriter w, byte[] b)
        {
            w.Write(b.Length);
            w.Write(b);
        }

        private static byte[] ReadBlob(BinaryReader r)
        {
            int n = r.ReadInt32();
            if (n < 0 || n > 4096) throw new InvalidDataException("Bad key data.");
            byte[] b = r.ReadBytes(n);
            if (b.Length != n) throw new EndOfStreamException();
            return b;
        }

        public static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        public static byte[] RandomBytes(int n)
        {
            byte[] b = new byte[n];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return b;
        }

        public static string ToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        public static byte[] FromHex(string hex)
        {
            if (hex == null || hex.Length % 2 != 0) throw new FormatException("Bad key id.");
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }
    }
}
