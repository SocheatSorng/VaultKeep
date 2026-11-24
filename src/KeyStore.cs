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

    /// <summary>
    /// A key found on a plugged-in drive. The ID and public half are always readable (to match items and to
    /// register the key). The private half, which opens items, may be encrypted with a PIN: then
    /// <see cref="TryUnlock"/> must succeed before <see cref="PrivateKey"/> can be used.
    /// </summary>
    internal sealed class KeyFile
    {
        public byte[] Id;
        public string Label;
        public string Path;
        public RSAParameters PublicKey;

        internal RSAParameters? Private;   // set when not PIN-protected, or after TryUnlock
        internal PinBox PinBox;            // set when the private half is PIN-protected

        public string IdHex { get { return KeyStore.ToHex(Id); } }
        public bool NeedsPin { get { return PinBox != null; } }
        public bool IsUnlocked { get { return Private.HasValue; } }

        public RSAParameters PrivateKey
        {
            get
            {
                if (!Private.HasValue) throw new InvalidOperationException("Enter the key's PIN first.");
                return Private.Value;
            }
        }

        /// <summary>Decrypts the private half with <paramref name="pin"/>. False if the PIN is wrong.</summary>
        public bool TryUnlock(string pin)
        {
            if (Private.HasValue) return true;
            if (PinBox == null || pin == null) return false;
            byte[] blob = PinBox.Open(pin);
            if (blob == null) return false;
            try { Private = KeyStore.ParsePrivateBlob(blob, PublicKey); }
            finally { Array.Clear(blob, 0, blob.Length); }
            return true;
        }
    }

    /// <summary>
    /// The PIN-encrypted private half of a key:
    ///   iterations (int32) | salt (16) | iv (16) | ciphertext (int32 length + bytes) | tag (32)
    ///   master = PBKDF2-HMAC-SHA256(PIN, salt, iterations) -> 32 bytes
    ///   encKey = HMAC(master, "VaultKeep key pin enc"), macKey = HMAC(master, "VaultKeep key pin mac")
    ///   ciphertext = AES-256-CBC(encKey, iv, private blob); tag = HMAC(macKey, header + everything before it)
    /// The tag also covers the key ID and public half, so they can't be swapped onto another key's PIN box.
    /// </summary>
    internal sealed class PinBox
    {
        public const int MinPinLength = 6;
        private static readonly byte[] EncLabel = Encoding.ASCII.GetBytes("VaultKeep key pin enc");
        private static readonly byte[] MacLabel = Encoding.ASCII.GetBytes("VaultKeep key pin mac");

        public int Iterations;
        public byte[] Salt, Iv, Cipher, Tag;
        public byte[] Bound; // key ID + public half, authenticated by the tag

        public static PinBox Seal(byte[] blob, string pin, byte[] bound)
        {
            var box = new PinBox
            {
                Iterations = VaultCrypto.DefaultIterations,
                Salt = KeyStore.RandomBytes(16),
                Iv = KeyStore.RandomBytes(16),
                Bound = bound
            };
            byte[] encKey, macKey;
            box.DeriveKeys(pin, out encKey, out macKey);
            try
            {
                using (var aes = new AesCryptoServiceProvider { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, Key = encKey, IV = box.Iv })
                using (ICryptoTransform t = aes.CreateEncryptor())
                    box.Cipher = t.TransformFinalBlock(blob, 0, blob.Length);
                box.Tag = box.ComputeTag(macKey);
                return box;
            }
            finally
            {
                Array.Clear(encKey, 0, encKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        /// <summary>The decrypted private blob, or null if the PIN is wrong (or the file was tampered with).</summary>
        public byte[] Open(string pin)
        {
            byte[] encKey, macKey;
            DeriveKeys(pin, out encKey, out macKey);
            try
            {
                if (!KeyStore.BytesEqual(ComputeTag(macKey), Tag)) return null;
                using (var aes = new AesCryptoServiceProvider { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, Key = encKey, IV = Iv })
                using (ICryptoTransform t = aes.CreateDecryptor())
                    return t.TransformFinalBlock(Cipher, 0, Cipher.Length);
            }
            catch (CryptographicException) { return null; }
            finally
            {
                Array.Clear(encKey, 0, encKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }
        }

        private void DeriveKeys(string pin, out byte[] encKey, out byte[] macKey)
        {
            byte[] pwd = Encoding.UTF8.GetBytes(pin);
            byte[] master = Pbkdf2.DeriveSha256(pwd, Salt, Iterations, 32);
            Array.Clear(pwd, 0, pwd.Length);
            try
            {
                using (var h = new HMACSHA256(master))
                {
                    encKey = h.ComputeHash(EncLabel);
                    macKey = h.ComputeHash(MacLabel);
                }
            }
            finally { Array.Clear(master, 0, master.Length); }
        }

        private byte[] ComputeTag(byte[] macKey)
        {
            var ms = new MemoryStream();
            ms.Write(Bound, 0, Bound.Length);
            ms.Write(BitConverter.GetBytes(Iterations), 0, 4);
            ms.Write(Salt, 0, Salt.Length);
            ms.Write(Iv, 0, Iv.Length);
            ms.Write(Cipher, 0, Cipher.Length);
            using (var h = new HMACSHA256(macKey)) return h.ComputeHash(ms.ToArray());
        }
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
        private static readonly byte[] KeyMagic = Encoding.ASCII.GetBytes("VKKEY1");  // VaultKeep 0.2, read only
        private static readonly byte[] KeyMagic2 = Encoding.ASCII.GetBytes("VKKEY2"); // optional PIN
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
                PublicKey = new RSAParameters { Modulus = key.PublicKey.Modulus, Exponent = key.PublicKey.Exponent }
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

        /// <summary>
        /// Creates a new key on the drive/folder <paramref name="root"/> and registers it. The private half is
        /// encrypted with <paramref name="pin"/>; null (test build only) leaves it unprotected.
        /// </summary>
        public static KeyFile CreateKey(string root, string label, string pin)
        {
            string path = KeyFilePath(root);
            if (File.Exists(path))
                throw new IOException("This drive already holds a VaultKeep key.");
            if (pin != null && pin.Length < PinBox.MinPinLength)
                throw new ArgumentException("The PIN must have at least " + PinBox.MinPinLength + " characters.");

            var key = new KeyFile { Id = RandomBytes(16), Label = label ?? "", Path = path };
            using (var rsa = new RSACng(RsaBits))
            {
                RSAParameters p = rsa.ExportParameters(true);
                key.PublicKey = new RSAParameters { Modulus = p.Modulus, Exponent = p.Exponent };
                key.Private = p;
            }

            var dir = Directory.CreateDirectory(Path.GetDirectoryName(path));
            dir.Attributes |= FileAttributes.Hidden;
            WriteKeyFile(path, key, pin, false);

            // Prove the written key reads back (and the PIN opens it) before telling anyone it exists.
            KeyFile check = ReadKeyFile(path);
            if (check == null || !BytesEqual(check.Id, key.Id) || (pin != null && !check.TryUnlock(pin)))
                throw new IOException("Couldn't write the key to this drive.");

            Register(key);
            return key;
        }

        /// <summary>
        /// Sets, changes or (test build) removes the PIN of the key at <paramref name="path"/>.
        /// <paramref name="oldPin"/> is ignored for a key that has no PIN yet. Returns false if the old PIN is wrong.
        /// </summary>
        public static bool ChangePin(string path, string oldPin, string newPin)
        {
            KeyFile key = ReadKeyFile(path);
            if (key == null) throw new InvalidDataException("This isn't a valid VaultKeep key file.");
            if (key.NeedsPin && !key.TryUnlock(oldPin)) return false;
            if (newPin != null && newPin.Length < PinBox.MinPinLength)
                throw new ArgumentException("The PIN must have at least " + PinBox.MinPinLength + " characters.");
            WriteKeyFile(path, key, newPin, true);
            return true;
        }

        /// <summary>Writes a key file (format VKKEY2) via a temp file, replacing an existing one if asked.</summary>
        private static void WriteKeyFile(string path, KeyFile key, string pin, bool replace)
        {
            var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8))
            {
                w.Write(KeyMagic2);
                byte[] bound = PublicHeader(key);
                w.Write(bound);
                byte[] blob = PrivateBlob(key.PrivateKey);
                try
                {
                    if (pin == null)
                    {
                        w.Write((byte)0);
                        WriteBlob(w, blob);
                    }
                    else
                    {
                        PinBox box = PinBox.Seal(blob, pin, bound);
                        w.Write((byte)1);
                        w.Write(box.Iterations);
                        w.Write(box.Salt);
                        w.Write(box.Iv);
                        WriteBlob(w, box.Cipher);
                        w.Write(box.Tag);
                    }
                }
                finally { Array.Clear(blob, 0, blob.Length); }
            }
            string temp = path + ".tmp";
            File.WriteAllBytes(temp, ms.ToArray());
            if (replace && File.Exists(path))
            {
                File.SetAttributes(path, FileAttributes.Normal);
                File.Replace(temp, path, null, true);
            }
            else
            {
                File.Move(temp, path);
            }
        }

        /// <summary>Key ID, label and public half, as written after the magic (and bound into the PIN tag).</summary>
        private static byte[] PublicHeader(KeyFile key)
        {
            var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms, Encoding.UTF8))
            {
                w.Write(key.Id);
                w.Write(key.Label ?? "");
                WriteBlob(w, key.PublicKey.Modulus);
                WriteBlob(w, key.PublicKey.Exponent);
            }
            return ms.ToArray();
        }

        private static byte[] PrivateBlob(RSAParameters p)
        {
            var ms = new MemoryStream();
            using (var w = new BinaryWriter(ms))
                foreach (byte[] part in new[] { p.D, p.P, p.Q, p.DP, p.DQ, p.InverseQ })
                    WriteBlob(w, part);
            return ms.ToArray();
        }

        internal static RSAParameters ParsePrivateBlob(byte[] blob, RSAParameters pub)
        {
            using (var r = new BinaryReader(new MemoryStream(blob)))
            {
                var p = new RSAParameters
                {
                    Modulus = pub.Modulus, Exponent = pub.Exponent,
                    D = ReadBlob(r), P = ReadBlob(r), Q = ReadBlob(r), DP = ReadBlob(r), DQ = ReadBlob(r), InverseQ = ReadBlob(r)
                };
                using (var rsa = new RSACng()) rsa.ImportParameters(p); // validates the key
                return p;
            }
        }

        /// <summary>
        /// Reads a key file without needing its PIN; returns null if it isn't a valid VaultKeep key.
        /// VKKEY1 (VaultKeep 0.2, no PIN): magic | id | label | modulus | exponent | D | P | Q | DP | DQ | InverseQ
        /// VKKEY2: magic | id | label | modulus | exponent | protection (0 = none, 1 = PIN) | private part
        /// </summary>
        public static KeyFile ReadKeyFile(string path)
        {
            try
            {
                byte[] data = File.ReadAllBytes(path);
                using (var r = new BinaryReader(new MemoryStream(data), Encoding.UTF8))
                {
                    byte[] magic = r.ReadBytes(KeyMagic.Length);
                    bool v2 = BytesEqual(magic, KeyMagic2);
                    if (!v2 && !BytesEqual(magic, KeyMagic)) return null;

                    var key = new KeyFile { Id = r.ReadBytes(16), Label = r.ReadString(), Path = path };
                    key.PublicKey = new RSAParameters { Modulus = ReadBlob(r), Exponent = ReadBlob(r) };
                    if (!v2)
                    {
                        var rest = new MemoryStream();
                        for (int i = 0; i < 6; i++) WriteBlob(new BinaryWriter(rest), ReadBlob(r));
                        key.Private = ParsePrivateBlob(rest.ToArray(), key.PublicKey);
                        return key;
                    }

                    byte protection = r.ReadByte();
                    if (protection == 0)
                    {
                        key.Private = ParsePrivateBlob(ReadBlob(r), key.PublicKey);
                    }
                    else if (protection == 1)
                    {
                        var box = new PinBox
                        {
                            Iterations = r.ReadInt32(),
                            Salt = r.ReadBytes(16),
                            Iv = r.ReadBytes(16),
                            Cipher = ReadBlob(r, 8192),
                            Tag = r.ReadBytes(32),
                            Bound = PublicHeader(key)
                        };
                        if (box.Iterations < VaultCrypto.MinIterations || box.Iterations > VaultCrypto.MaxIterations ||
                            box.Salt.Length != 16 || box.Iv.Length != 16 || box.Tag.Length != 32)
                            return null;
                        key.PinBox = box;
                    }
                    else return null;
                    using (var rsa = new RSACng()) rsa.ImportParameters(key.PublicKey); // validates the public half
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
            return ReadBlob(r, 4096);
        }

        private static byte[] ReadBlob(BinaryReader r, int max)
        {
            int n = r.ReadInt32();
            if (n < 0 || n > max) throw new InvalidDataException("Bad key data.");
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
