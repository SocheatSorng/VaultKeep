using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace VaultKeep
{
    /// <summary>
    /// HMAC-SHA256 computed on a background thread. SHA-256 is the slowest step for large items (about
    /// 190 MB/s on CPUs without SHA instructions, versus ~750 MB/s for AES), so hashing in parallel with
    /// encryption/decryption and disk I/O lets lock and unlock run in one pass at close to hashing speed.
    /// </summary>
    internal sealed class BackgroundHmac : IDisposable
    {
        private const int ChunkSize = 1 << 20;
        private const int QueueDepth = 8;

        private struct Chunk
        {
            public byte[] Data;
            public int Count;
        }

        private readonly HMACSHA256 _hmac;
        private readonly BlockingCollection<Chunk> _queue = new BlockingCollection<Chunk>(QueueDepth);
        // Reused 1 MB buffers: allocating a fresh large array per chunk (thousands for a multi-GB item)
        // puts heavy pressure on the large-object heap.
        private readonly ConcurrentBag<byte[]> _pool = new ConcurrentBag<byte[]>();
        private readonly Thread _thread;
        private Exception _error;
        private byte[] _result;

        public BackgroundHmac(byte[] key)
        {
            _hmac = new HMACSHA256(key);
            _thread = new Thread(Run) { IsBackground = true, Name = "VaultKeep HMAC" };
            _thread.Start();
        }

        public void Add(byte[] buffer, int offset, int count)
        {
            while (count > 0)
            {
                if (_error != null) throw new IOException("Hashing failed.", _error);
                int n = Math.Min(count, ChunkSize);
                byte[] data;
                if (!_pool.TryTake(out data)) data = new byte[ChunkSize];
                Buffer.BlockCopy(buffer, offset, data, 0, n);
                _queue.Add(new Chunk { Data = data, Count = n });
                offset += n;
                count -= n;
            }
        }

        /// <summary>Waits for all queued data to be hashed and returns the HMAC.</summary>
        public byte[] Finish()
        {
            if (_result != null) return _result;
            _queue.CompleteAdding();
            _thread.Join();
            if (_error != null) throw new IOException("Hashing failed.", _error);
            _hmac.TransformFinalBlock(new byte[0], 0, 0);
            _result = _hmac.Hash;
            return _result;
        }

        private void Run()
        {
            try
            {
                foreach (Chunk chunk in _queue.GetConsumingEnumerable())
                {
                    _hmac.TransformBlock(chunk.Data, 0, chunk.Count, null, 0);
                    _pool.Add(chunk.Data);
                }
            }
            catch (Exception ex)
            {
                _error = ex;
                // Keep draining so producers blocked on a full queue can't hang.
                foreach (Chunk ignored in _queue.GetConsumingEnumerable()) { }
            }
        }

        public void Dispose()
        {
            if (!_queue.IsAddingCompleted) _queue.CompleteAdding();
            _thread.Join();
            _hmac.Dispose();
            _queue.Dispose();
        }
    }

    /// <summary>Write-through stream that also feeds everything written into a <see cref="BackgroundHmac"/>.</summary>
    internal sealed class HashingWriteStream : Stream
    {
        private readonly Stream _inner;
        private readonly BackgroundHmac _mac;

        public HashingWriteStream(Stream inner, BackgroundHmac mac)
        {
            _inner = inner;
            _mac = mac;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _mac.Add(buffer, offset, count);
            _inner.Write(buffer, offset, count);
        }

        public override void WriteByte(byte value)
        {
            Write(new[] { value }, 0, 1);
        }

        public override void Flush() { _inner.Flush(); }
        public override bool CanRead { get { return false; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return true; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
    }

    /// <summary>Read-through stream that feeds everything read into a <see cref="BackgroundHmac"/> and reports progress.</summary>
    internal sealed class HashingReadStream : Stream
    {
        private readonly Stream _inner;
        private readonly BackgroundHmac _mac;

        public HashingReadStream(Stream inner, BackgroundHmac mac)
        {
            _inner = inner;
            _mac = mac;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = _inner.Read(buffer, offset, count);
            _mac.Add(buffer, offset, n);
            Progress.Add(n);
            return n;
        }

        public override void Flush() { }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    }

    /// <summary>
    /// Progress of the lock/unlock running on the current thread. Whoever starts the work sets <see cref="Hook"/>
    /// (percent 0-100) on that thread; VaultCrypto calls <see cref="Begin"/> and <see cref="Add"/>.
    /// </summary>
    internal static class Progress
    {
        [ThreadStatic] public static Action<int> Hook;
        [ThreadStatic] private static long _done;
        [ThreadStatic] private static long _total;
        [ThreadStatic] private static int _lastPercent;

        public static void Begin(long total)
        {
            _done = 0;
            _total = total;
            _lastPercent = -1;
            Report();
        }

        public static void Add(long bytes)
        {
            if (bytes <= 0) return;
            _done += bytes;
            Report();
        }

        private static void Report()
        {
            Action<int> hook = Hook;
            if (hook == null) return;
            int percent = _total <= 0 ? 0 : (int)Math.Min(100, _done * 100 / _total);
            if (percent == _lastPercent) return;
            _lastPercent = percent;
            try { hook(percent); } catch { }
        }
    }
}
