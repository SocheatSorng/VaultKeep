using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VaultKeep
{
    /// <summary>
    /// The keys of one locked item (format v3): a random 64-byte data key (DEK = encKey 32 + macKey 32) and the
    /// "slots" that each hold a wrapped copy of it. Any one slot opens the item:
    ///
    ///   slot = type (1) | length (uint16) | data
    ///   type 1, password:  iterations (int32) | salt (16) | iv (16) | wrapped DEK (64) | tag (32)
    ///       master = PBKDF2-HMAC-SHA256(password, salt, iterations) -> 32 bytes
    ///       kekEnc = HMAC(master, "VaultKeep v3 kek enc"), kekMac = HMAC(master, "VaultKeep v3 kek mac")
    ///       wrapped = AES-256-CBC(kekEnc, iv, DEK) without padding; tag = HMAC(kekMac, iterations..wrapped)
    ///   type 2, USB key:   key id (16) | RSA-OAEP-SHA256(public key, DEK)
    ///
    /// The whole file (including all slots) is also covered by the file HMAC made with the DEK's macKey,
    /// so slots can't be swapped or edited without detection.
    /// </summary>
    internal sealed class VaultKeys
    {
        public const byte SlotPassword = 1;
        public const byte SlotUsbKey = 2;
        private const int DekSize = 64;

        private static readonly byte[] KekEncLabel = Encoding.ASCII.GetBytes("VaultKeep v3 kek enc");
        private static readonly byte[] KekMacLabel = Encoding.ASCII.GetBytes("VaultKeep v3 kek mac");

        private readonly byte[] _dek;
        private readonly List<byte[]> _slots;

        private VaultKeys(byte[] dek, List<byte[]> slots)
        {
            _dek = dek;
            _slots = slots;
        }

        public byte[] EncKey { get { return Slice(_dek, 0, 32); } }
        public byte[] MacKey { get { return Slice(_dek, 32, 32); } }
        public IList<byte[]> Slots { get { return _slots.AsReadOnly(); } }

        public bool HasPasswordSlot
        {
            get
            {
                foreach (byte[] s in _slots) if (s[0] == SlotPassword) return true;
                return false;
            }
        }

        /// <summary>New random data key, wrapped by the password and by every registered USB key.</summary>
        public static VaultKeys CreateNew(string password, IEnumerable<RegisteredKey> keys)
        {
            var vk = new VaultKeys(KeyStore.RandomBytes(DekSize), new List<byte[]>());
            vk._slots.Add(MakePasswordSlot(vk._dek, password, VaultCrypto.DefaultIterations));
            vk.SyncKeySlots(keys);
            return vk;
        }

        /// <summary>Existing data key + slots read from a file (used to re-lock an opened item).</summary>
        public static VaultKeys FromExisting(byte[] dek, List<byte[]> slots)
        {
            return new VaultKeys(dek, slots);
        }

        /// <summary>
        /// Makes the USB-key slots match the keys registered on this PC: adds missing ones, and drops slots of
        /// keys that were removed here (e.g. a lost drive). The password slot is always kept.
        /// </summary>
        public void SyncKeySlots(IEnumerable<RegisteredKey> keys)
        {
            var wanted = new List<RegisteredKey>(keys ?? new RegisteredKey[0]);
            _slots.RemoveAll(s => s[0] == SlotUsbKey && !wanted.Exists(k => KeyStore.BytesEqual(k.Id, SlotKeyId(s))));
            foreach (RegisteredKey k in wanted)
            {
                bool present = _slots.Exists(s => s[0] == SlotUsbKey && KeyStore.BytesEqual(k.Id, SlotKeyId(s)));
                if (!present) _slots.Add(MakeKeySlot(_dek, k));
            }
        }

        public void Clear()
        {
            Array.Clear(_dek, 0, _dek.Length);
        }

        // ------------------------------------------------------------ Slots

        private static byte[] MakePasswordSlot(byte[] dek, string password, int iterations)
        {
            byte[] salt = KeyStore.RandomBytes(16);
            byte[] iv = KeyStore.RandomBytes(16);
            byte[] kekEnc, kekMac;
            DerivePasswordKek(password, salt, iterations, out kekEnc, out kekMac);
            try
            {
                byte[] wrapped = AesNoPad(kekEnc, iv, dek, true);
                var body = new MemoryStream();
                body.Write(BitConverter.GetBytes(iterations), 0, 4);
                body.Write(salt, 0, 16);
                body.Write(iv, 0, 16);
                body.Write(wrapped, 0, wrapped.Length);
                byte[] tag;
                using (var h = new HMACSHA256(kekMac)) tag = h.ComputeHash(body.ToArray());
                body.Write(tag, 0, tag.Length);
                return Encode(SlotPassword, body.ToArray());
            }
            finally
            {
                Array.Clear(kekEnc, 0, kekEnc.Length);
                Array.Clear(kekMac, 0, kekMac.Length);
            }
        }

        private static byte[] MakeKeySlot(byte[] dek, RegisteredKey key)
        {
            byte[] wrapped;
            using (var rsa = new RSACng())
            {
                rsa.ImportParameters(key.PublicKey);
                wrapped = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
            }
            byte[] data = new byte[16 + wrapped.Length];
            Buffer.BlockCopy(key.Id, 0, data, 0, 16);
            Buffer.BlockCopy(wrapped, 0, data, 16, wrapped.Length);
            return Encode(SlotUsbKey, data);
        }

        /// <summary>Unwraps the DEK with a password. Returns null if no password slot accepts it.</summary>
        public static byte[] OpenWithPassword(IList<byte[]> slots, string password)
        {
            foreach (byte[] slot in slots)
            {
                if (slot[0] != SlotPassword) continue;
                byte[] data = Data(slot);
                if (data.Length != 4 + 16 + 16 + 64 + 32) continue;
                int iterations = BitConverter.ToInt32(data, 0);
                if (iterations < VaultCrypto.MinIterations || iterations > VaultCrypto.MaxIterations) continue;
                byte[] salt = Slice(data, 4, 16), iv = Slice(data, 20, 16), wrapped = Slice(data, 36, 64), tag = Slice(data, 100, 32);
                byte[] kekEnc, kekMac;
                DerivePasswordKek(password, salt, iterations, out kekEnc, out kekMac);
                try
                {
                    byte[] expected;
                    using (var h = new HMACSHA256(kekMac)) expected = h.ComputeHash(data, 0, 100);
                    if (!KeyStore.BytesEqual(expected, tag)) continue;
                    return AesNoPad(kekEnc, iv, wrapped, false);
                }
                finally
                {
                    Array.Clear(kekEnc, 0, kekEnc.Length);
                    Array.Clear(kekMac, 0, kekMac.Length);
                }
            }
            return null;
        }

        /// <summary>Unwraps the DEK with a USB key. Returns null if the item has no slot for this key.</summary>
        public static byte[] OpenWithKey(IList<byte[]> slots, KeyFile key)
        {
            foreach (byte[] slot in slots)
            {
                if (slot[0] != SlotUsbKey || !KeyStore.BytesEqual(SlotKeyId(slot), key.Id)) continue;
                byte[] data = Data(slot);
                try
                {
                    using (var rsa = new RSACng())
                    {
                        rsa.ImportParameters(key.PrivateKey);
                        byte[] dek = rsa.Decrypt(Slice(data, 16, data.Length - 16), RSAEncryptionPadding.OaepSHA256);
                        if (dek.Length == DekSize) return dek;
                    }
                }
                catch (CryptographicException) { }
            }
            return null;
        }

        public static bool HasSlotFor(IList<byte[]> slots, KeyFile key)
        {
            foreach (byte[] s in slots)
                if (s[0] == SlotUsbKey && KeyStore.BytesEqual(SlotKeyId(s), key.Id)) return true;
            return false;
        }

        // ---------------------------------------------------------------- Helpers

        private static void DerivePasswordKek(string password, byte[] salt, int iterations, out byte[] kekEnc, out byte[] kekMac)
        {
            byte[] pwd = Encoding.UTF8.GetBytes(password);
            byte[] master = Pbkdf2.DeriveSha256(pwd, salt, iterations, 32);
            Array.Clear(pwd, 0, pwd.Length);
            try
            {
                using (var h = new HMACSHA256(master))
                {
                    kekEnc = h.ComputeHash(KekEncLabel);
                    kekMac = h.ComputeHash(KekMacLabel);
                }
            }
            finally
            {
                Array.Clear(master, 0, master.Length);
            }
        }

        private static byte[] AesNoPad(byte[] key, byte[] iv, byte[] input, bool encrypt)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.Key = key;
                aes.IV = iv;
                using (ICryptoTransform t = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                    return t.TransformFinalBlock(input, 0, input.Length);
            }
        }

        private static byte[] Encode(byte type, byte[] data)
        {
            byte[] slot = new byte[3 + data.Length];
            slot[0] = type;
            slot[1] = (byte)(data.Length & 0xFF);
            slot[2] = (byte)(data.Length >> 8);
            Buffer.BlockCopy(data, 0, slot, 3, data.Length);
            return slot;
        }

        private static byte[] Data(byte[] slot)
        {
            return Slice(slot, 3, slot.Length - 3);
        }

        private static byte[] SlotKeyId(byte[] slot)
        {
            return slot.Length >= 3 + 16 ? Slice(slot, 3, 16) : new byte[0];
        }

        private static byte[] Slice(byte[] b, int offset, int count)
        {
            byte[] r = new byte[count];
            Buffer.BlockCopy(b, offset, r, 0, count);
            return r;
        }
    }
}
