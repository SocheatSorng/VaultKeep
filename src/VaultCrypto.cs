using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VaultKeep
{
    /// <summary>
    /// .vkl file layout (all integers little-endian):
    ///   magic "VKL1" (4) | version (1) | kind (1) | iterations (int32) | salt (16) | iv (16)
    ///   | AES-256-CBC ciphertext of the payload | HMAC-SHA256 over everything before it (32)
    ///
    /// Keys:
    ///   version 2 (written now): master = PBKDF2-HMAC-SHA256(password, salt, iterations) -> 32 bytes;
    ///     encKey = HMAC-SHA256(master, "VaultKeep v2 enc"), macKey = HMAC-SHA256(master, "VaultKeep v2 mac").
    ///     One PBKDF2 block, so the user pays the same work per guess as an attacker does.
    ///   version 1 (read only): PBKDF2-HMAC-SHA256 -> 64 bytes = encKey(32) + macKey(32).
    ///
    /// Payload (BinaryWriter format, strings are length-prefixed UTF-8):
    ///   kind = file:   name | lastWriteUtcTicks (int64) | length (int64) | bytes
    ///   kind = folder: name | entries... | 0
    ///     entry dir  = 1 | relativePath
    ///     entry file = 2 | relativePath | lastWriteUtcTicks | length | bytes
    /// </summary>
    internal static class VaultCrypto
    {
        public const string Extension = ".vkl";
        public const int DefaultIterations = 600000; // OWASP 2023+ guidance for PBKDF2-HMAC-SHA256

        private static readonly byte[] Magic = { (byte)'V', (byte)'K', (byte)'L', (byte)'1' };
        private const byte FormatVersion = 2;
        private const byte OldestReadableVersion = 1;
        private const byte KindFile = 0;
        private const byte KindFolder = 1;
        private const int SaltSize = 16;
        private const int IvSize = 16;
        private const int MacSize = 32;
        private const int HeaderSize = 4 + 1 + 1 + 4 + SaltSize + IvSize;
        private const int MinIterations = 10000;
        private const int MaxIterations = 10000000;
        private const byte EntryEnd = 0;
        private const byte EntryDir = 1;
        private const byte EntryFile = 2;
        private const int BufferSize = 1 << 20;

        // ------------------------------------------------------------------ Lock

        /// <summary>Encrypts a file or folder into "&lt;name&gt;.vkl" next to it, then deletes the original.</summary>
        /// <param name="replaceStale">
        /// Replace an existing "&lt;name&gt;.vkl" (an older locked copy of this same item, e.g. left behind when
        /// re-locking after use). When false, an existing .vkl is an error so nothing is ever overwritten.
        /// </param>
        public static LockResult Lock(string sourcePath, string password)
        {
            return Lock(sourcePath, password, false);
        }

        public static LockResult Lock(string sourcePath, string password, bool replaceStale)
        {
            string full = Path.GetFullPath(sourcePath).TrimEnd('\\');
            bool isFolder = Directory.Exists(full);
            if (!isFolder && !File.Exists(full))
                throw new FileNotFoundException("The file or folder no longer exists.", full);
            if (full.EndsWith(Extension, StringComparison.OrdinalIgnoreCase) && !isFolder)
                throw new InvalidOperationException("This item is already locked.");

            string parent = Path.GetDirectoryName(full);
            if (string.IsNullOrEmpty(parent))
                throw new InvalidOperationException("Locking an entire drive is not supported.");

            if (isFolder)
                EnsureNoReparsePoints(full);

            string name = Path.GetFileName(full);
            string output = Path.Combine(parent, name + Extension);
            bool replacing = false;
            if (Directory.Exists(output))
                throw new IOException("A folder named \"" + Path.GetFileName(output) + "\" already exists here.");
            if (File.Exists(output))
            {
                if (!replaceStale || !IsVaultFile(output))
                    throw new IOException("\"" + Path.GetFileName(output) + "\" already exists in this folder.");
                replacing = true;
            }

            // Write to a hidden temp file and rename it into place only when complete, so a crash or
            // power cut never leaves a half-written file under the real .vkl name.
            string temp = Path.Combine(parent, "." + name + ".vkl-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp");

            byte[] salt = RandomBytes(SaltSize);
            byte[] iv = RandomBytes(IvSize);
            byte[] encKey, macKey;
            DeriveKeys(password, salt, DefaultIterations, FormatVersion, out encKey, out macKey);

            try
            {
                using (var fs = new FileStream(temp, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                {
                    File.SetAttributes(temp, FileAttributes.Hidden);
                    WriteHeader(fs, isFolder ? KindFolder : KindFile, DefaultIterations, salt, iv);

                    using (var aes = CreateAes(encKey, iv))
                    using (var encryptor = aes.CreateEncryptor())
                    using (var cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write, true))
                    using (var w = new BinaryWriter(cs, Encoding.UTF8, true))
                    {
                        byte[] buffer = new byte[BufferSize];
                        w.Write(name);
                        if (isFolder)
                        {
                            WriteFolderEntries(w, full, full, buffer);
                            w.Write(EntryEnd);
                        }
                        else
                        {
                            WriteFileBody(w, full, buffer);
                        }
                        w.Flush();
                        cs.FlushFinalBlock();
                    }

                    // Encrypt-then-MAC: authenticate header + ciphertext.
                    fs.Position = 0;
                    byte[] mac = ComputeMac(fs, macKey, fs.Length);
                    fs.Position = fs.Length;
                    fs.Write(mac, 0, mac.Length);
                    fs.Flush(true);
                }

                File.SetAttributes(temp, FileAttributes.Normal);
                if (replacing)
                    File.Replace(temp, output, null, true);
                else
                    File.Move(temp, output);
            }
            catch
            {
                TryDeleteFile(temp);
                throw;
            }
            finally
            {
                Array.Clear(encKey, 0, encKey.Length);
                Array.Clear(macKey, 0, macKey.Length);
            }

            // Only remove the original once the locked copy is fully written.
            var result = new LockResult { OutputPath = output };
            if (isFolder)
                DeleteFolder(full, result.UndeletedItems);
            else
                DeleteFileOrRecord(full, result.UndeletedItems);
            return result;
        }

        private static void WriteFileBody(BinaryWriter w, string path, byte[] buffer)
        {
            using (var src = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan))
            {
                w.Write(File.GetLastWriteTimeUtc(path).Ticks);
                w.Write(src.Length);
                w.Flush();
                CopyExact(src, w.BaseStream, src.Length, buffer);
            }
        }

        private static void WriteFolderEntries(BinaryWriter w, string root, string dir, byte[] buffer)
        {
            foreach (string file in Directory.GetFiles(dir))
            {
                w.Write(EntryFile);
                w.Write(RelativePath(root, file));
                WriteFileBody(w, file, buffer);
            }
            foreach (string sub in Directory.GetDirectories(dir))
            {
                w.Write(EntryDir);
                w.Write(RelativePath(root, sub));
                WriteFolderEntries(w, root, sub, buffer);
            }
        }

        private static void EnsureNoReparsePoints(string dir)
        {
            foreach (string entry in Directory.EnumerateFileSystemEntries(dir, "*", SearchOption.AllDirectories))
            {
                if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0)
                    throw new NotSupportedException(
                        "This folder contains a shortcut link or junction (\"" + RelativePath(dir, entry) +
                        "\"), which VaultKeep can't lock yet.");
            }
        }

        // ---------------------------------------------------------------- Unlock

        /// <summary>Decrypts a .vkl file back to its original file/folder next to it, then deletes the .vkl.</summary>
        /// <returns>Path of the restored file or folder.</returns>
        /// <exception cref="WrongPasswordException">Password is wrong or the file was tampered with.</exception>
        public static string Unlock(string vklPath, string password)
        {
            string full = Path.GetFullPath(vklPath);
            string parent = Path.GetDirectoryName(full);
            string restored;

            using (var fs = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan))
            {
                if (fs.Length < HeaderSize + IvSize + MacSize)
                    throw new InvalidDataException("This is not a valid VaultKeep file.");

                byte version, kind;
                int iterations;
                byte[] salt, iv;
                ReadHeader(fs, out version, out kind, out iterations, out salt, out iv);

                byte[] encKey, macKey;
                DeriveKeys(password, salt, iterations, version, out encKey, out macKey);
                try
                {
                    long macOffset = fs.Length - MacSize;
                    fs.Position = 0;
                    byte[] expected = ComputeMac(fs, macKey, macOffset);
                    byte[] stored = new byte[MacSize];
                    fs.Position = macOffset;
                    ReadExact(fs, stored, MacSize);
                    if (!FixedTimeEquals(expected, stored))
                        throw new WrongPasswordException();

                    fs.Position = HeaderSize;
                    var cipher = new LimitedReadStream(fs, macOffset - HeaderSize);
                    using (var aes = CreateAes(encKey, iv))
                    using (var decryptor = aes.CreateDecryptor())
                    using (var cs = new CryptoStream(cipher, decryptor, CryptoStreamMode.Read))
                    using (var r = new BinaryReader(cs, Encoding.UTF8))
                    {
                        string name = r.ReadString();
                        ValidateName(name);
                        restored = Path.Combine(parent, name);
                        if (File.Exists(restored) || Directory.Exists(restored))
                            throw new IOException("\"" + name + "\" already exists in this folder. Move or rename it, then try again.");

                        byte[] buffer = new byte[BufferSize];
                        if (kind == KindFile)
                            RestoreFile(r, restored, buffer);
                        else if (kind == KindFolder)
                            RestoreFolder(r, parent, restored, buffer);
                        else
                            throw new InvalidDataException("Unknown item type in VaultKeep file.");
                    }
                }
                finally
                {
                    Array.Clear(encKey, 0, encKey.Length);
                    Array.Clear(macKey, 0, macKey.Length);
                }
            }

            TryDeleteFile(full);
            return restored;
        }

        private static void RestoreFile(BinaryReader r, string target, byte[] buffer)
        {
            string temp = target + ".vkpart";
            TryDeleteFile(temp);
            try
            {
                ExtractFileBody(r, temp, buffer);
                File.Move(temp, target);
            }
            catch
            {
                TryDeleteFile(temp);
                throw;
            }
        }

        private static void RestoreFolder(BinaryReader r, string parent, string target, byte[] buffer)
        {
            // Extract into a hidden temp folder first so a failure never leaves a half-restored folder.
            string temp = Path.Combine(parent, "." + Path.GetFileName(target) + ".vkpart-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            var tempInfo = Directory.CreateDirectory(temp);
            tempInfo.Attributes |= FileAttributes.Hidden;
            try
            {
                string root = Path.GetFullPath(temp).TrimEnd('\\') + "\\";
                while (true)
                {
                    byte type = r.ReadByte();
                    if (type == EntryEnd) break;
                    string rel = r.ReadString();
                    string dest = SafeCombine(root, rel);
                    if (type == EntryDir)
                        Directory.CreateDirectory(dest);
                    else if (type == EntryFile)
                    {
                        Directory.CreateDirectory(Path.GetDirectoryName(dest));
                        ExtractFileBody(r, dest, buffer);
                    }
                    else
                        throw new InvalidDataException("Corrupt VaultKeep file.");
                }
                Directory.Move(temp, target);
                new DirectoryInfo(target).Attributes &= ~FileAttributes.Hidden;
            }
            catch
            {
                try { if (Directory.Exists(temp)) Directory.Delete(temp, true); } catch { }
                throw;
            }
        }

        private static void ExtractFileBody(BinaryReader r, string dest, byte[] buffer)
        {
            long ticks = r.ReadInt64();
            long length = r.ReadInt64();
            if (length < 0) throw new InvalidDataException("Corrupt VaultKeep file.");
            using (var outFs = new FileStream(dest, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                CopyExact(r.BaseStream, outFs, length, buffer);
            try { File.SetLastWriteTimeUtc(dest, new DateTime(ticks, DateTimeKind.Utc)); } catch { }
        }

        // ---------------------------------------------------------------- Helpers

        public static bool IsVaultFile(string path)
        {
            if (!File.Exists(path)) return false;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] m = new byte[4];
                    return fs.Read(m, 0, 4) == 4 && m[0] == Magic[0] && m[1] == Magic[1] && m[2] == Magic[2] && m[3] == Magic[3];
                }
            }
            catch { return false; }
        }

        private static void WriteHeader(Stream s, byte kind, int iterations, byte[] salt, byte[] iv)
        {
            s.Write(Magic, 0, Magic.Length);
            s.WriteByte(FormatVersion);
            s.WriteByte(kind);
            s.Write(BitConverter.GetBytes(iterations), 0, 4);
            s.Write(salt, 0, salt.Length);
            s.Write(iv, 0, iv.Length);
        }

        private static void ReadHeader(Stream s, out byte version, out byte kind, out int iterations, out byte[] salt, out byte[] iv)
        {
            byte[] h = new byte[HeaderSize];
            ReadExact(s, h, HeaderSize);
            for (int i = 0; i < Magic.Length; i++)
                if (h[i] != Magic[i]) throw new InvalidDataException("This is not a VaultKeep file.");
            version = h[4];
            if (version > FormatVersion)
                throw new InvalidDataException("This file was made by a newer version of VaultKeep.");
            if (version < OldestReadableVersion)
                throw new InvalidDataException("Corrupt VaultKeep file header.");
            kind = h[5];
            iterations = BitConverter.ToInt32(h, 6);
            if (iterations < MinIterations || iterations > MaxIterations)
                throw new InvalidDataException("Corrupt VaultKeep file header.");
            salt = new byte[SaltSize];
            iv = new byte[IvSize];
            Buffer.BlockCopy(h, 10, salt, 0, SaltSize);
            Buffer.BlockCopy(h, 10 + SaltSize, iv, 0, IvSize);
        }

        private static readonly byte[] EncLabel = Encoding.ASCII.GetBytes("VaultKeep v2 enc");
        private static readonly byte[] MacLabel = Encoding.ASCII.GetBytes("VaultKeep v2 mac");

        private static void DeriveKeys(string password, byte[] salt, int iterations, byte version, out byte[] encKey, out byte[] macKey)
        {
            byte[] pwd = Encoding.UTF8.GetBytes(password);
            try
            {
                if (version == 1)
                {
                    byte[] all = Pbkdf2.DeriveSha256(pwd, salt, iterations, 64);
                    encKey = new byte[32];
                    macKey = new byte[32];
                    Buffer.BlockCopy(all, 0, encKey, 0, 32);
                    Buffer.BlockCopy(all, 32, macKey, 0, 32);
                    Array.Clear(all, 0, all.Length);
                    return;
                }

                byte[] master = Pbkdf2.DeriveSha256(pwd, salt, iterations, 32);
                try
                {
                    using (var h = new HMACSHA256(master))
                    {
                        encKey = h.ComputeHash(EncLabel);
                        macKey = h.ComputeHash(MacLabel);
                    }
                }
                finally
                {
                    Array.Clear(master, 0, master.Length);
                }
            }
            finally
            {
                Array.Clear(pwd, 0, pwd.Length);
            }
        }

        private static Aes CreateAes(byte[] key, byte[] iv)
        {
            var aes = new AesCryptoServiceProvider();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = key;
            aes.IV = iv;
            return aes;
        }

        private static byte[] ComputeMac(Stream s, byte[] macKey, long count)
        {
            using (var h = new HMACSHA256(macKey))
            {
                byte[] buffer = new byte[BufferSize];
                long remaining = count;
                while (remaining > 0)
                {
                    int n = s.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                    if (n <= 0) throw new EndOfStreamException();
                    h.TransformBlock(buffer, 0, n, null, 0);
                    remaining -= n;
                }
                h.TransformFinalBlock(new byte[0], 0, 0);
                return h.Hash;
            }
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private static byte[] RandomBytes(int n)
        {
            byte[] b = new byte[n];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
            return b;
        }

        private static void CopyExact(Stream src, Stream dst, long count, byte[] buffer)
        {
            long remaining = count;
            while (remaining > 0)
            {
                int n = src.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
                if (n <= 0) throw new EndOfStreamException("The file changed or was truncated while being processed.");
                dst.Write(buffer, 0, n);
                remaining -= n;
            }
        }

        private static void ReadExact(Stream s, byte[] buffer, int count)
        {
            int read = 0;
            while (read < count)
            {
                int n = s.Read(buffer, read, count - read);
                if (n <= 0) throw new InvalidDataException("This VaultKeep file is truncated.");
                read += n;
            }
        }

        private static string RelativePath(string root, string path)
        {
            return path.Substring(root.TrimEnd('\\').Length + 1);
        }

        private static void ValidateName(string name)
        {
            if (string.IsNullOrEmpty(name) || name == "." || name == ".." ||
                name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                throw new InvalidDataException("Corrupt VaultKeep file (bad name).");
        }

        /// <summary>Combines root + relative path and refuses anything that escapes root.</summary>
        private static string SafeCombine(string rootWithSlash, string rel)
        {
            if (string.IsNullOrEmpty(rel) || Path.IsPathRooted(rel) || rel.Contains(":"))
                throw new InvalidDataException("Corrupt VaultKeep file (bad path).");
            foreach (string part in rel.Split('\\', '/'))
                if (part.Length == 0 || part == "." || part == "..")
                    throw new InvalidDataException("Corrupt VaultKeep file (bad path).");
            string full = Path.GetFullPath(Path.Combine(rootWithSlash, rel));
            if (!full.StartsWith(rootWithSlash, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Corrupt VaultKeep file (bad path).");
            return full;
        }

        private static void DeleteFolder(string dir, List<string> failures)
        {
            foreach (string file in Directory.GetFiles(dir))
                DeleteFileOrRecord(file, failures);
            foreach (string sub in Directory.GetDirectories(dir))
                DeleteFolder(sub, failures);
            try
            {
                new DirectoryInfo(dir).Attributes = FileAttributes.Directory;
                Directory.Delete(dir, false);
            }
            catch (Exception)
            {
                if (failures.Count == 0) failures.Add(dir);
            }
        }

        private static void DeleteFileOrRecord(string file, List<string> failures)
        {
            try
            {
                File.SetAttributes(file, FileAttributes.Normal);
                File.Delete(file);
            }
            catch (Exception)
            {
                failures.Add(file);
            }
        }

        private static void TryDeleteFile(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    File.SetAttributes(path, FileAttributes.Normal);
                    File.Delete(path);
                }
            }
            catch { }
        }
    }

    internal sealed class LockResult
    {
        public string OutputPath;
        public readonly List<string> UndeletedItems = new List<string>();
    }

    internal sealed class WrongPasswordException : Exception
    {
        public WrongPasswordException() : base("Wrong password (or the locked file is damaged).") { }
    }

    /// <summary>Read-only view over the next N bytes of a stream (used to stop before the trailing MAC).</summary>
    internal sealed class LimitedReadStream : Stream
    {
        private readonly Stream _inner;
        private long _remaining;

        public LimitedReadStream(Stream inner, long length)
        {
            _inner = inner;
            _remaining = length;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_remaining <= 0) return 0;
            int n = _inner.Read(buffer, offset, (int)Math.Min(count, _remaining));
            _remaining -= n;
            return n;
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    }
}
