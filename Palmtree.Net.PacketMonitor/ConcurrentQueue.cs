using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Palmtree.Net.PacketMonitor
{
    public class ConcurrentQueue<ELEMENT_T>
        : IDisposable
    {
        private bool _disposed;
        private ManualResetEventSlim _readyEvent;
        private Queue<ELEMENT_T> _imp;
        private CancellationTokenSource _cts;

        public ConcurrentQueue()
        {
            _disposed = false;
            _readyEvent = new ManualResetEventSlim();
            _imp = new Queue<ELEMENT_T>();
            _cts = new CancellationTokenSource();
        }

        public void Enqueue(ELEMENT_T element)
        {
            lock (this)
            {
                _imp.Enqueue(element);
                _readyEvent.Set();
            }
        }

        public void Cancel()
        {
            _cts.Cancel();
        }

        public Task<ELEMENT_T> Dequeue()
        {
            var ct = _cts.Token;
            return
                Task.Run(() =>
                {
                    _readyEvent.Wait(ct);
                    var element = _imp.Dequeue();
                    if (_imp.Any())
                        _readyEvent.Set();
                    else
                        _readyEvent.Reset();
                    return element;
                });
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                }

                try
                {
                    if (_cts != null)
                    {
                        _cts.Cancel();
                        _cts.Dispose();
                        _cts = null;
                    }

                    if (_readyEvent != null)
                    {
                        _readyEvent.Dispose();
                        _readyEvent = null;
                    }
                }
                catch (Exception)
                {
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
