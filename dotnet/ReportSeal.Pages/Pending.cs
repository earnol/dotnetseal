using System;
using System.Threading;
using System.Threading.Tasks;

namespace ReportSeal.Pages
{
    /// <summary>
    /// A result that is available now or will be later: a fetched key table, or a
    /// signature check. An asynchronous implementation creates one, returns it, and
    /// calls <see cref="Complete"/> or <see cref="Fail"/> when its answer arrives —
    /// from a browser callback, for instance.
    ///
    /// <see cref="PageSealer.BeginSeal"/> only ever polls it, so it works on a
    /// single-threaded host. The synchronous <see cref="PageSealer.Seal"/> can wait for
    /// one made by <see cref="FromTask"/>, which completes on another thread, and
    /// refuses any other kind rather than spinning forever.
    /// </summary>
    public sealed class Pending<T>
    {
        private readonly Task task;
        private T result;
        private Exception error;
        private volatile bool done;

        public Pending() { }

        private Pending(Task task)
        {
            this.task = task;
        }

        /// <summary>True once there is either a result or an error.</summary>
        public bool IsComplete => done;

        /// <summary>The result, once complete and successful; default otherwise.</summary>
        public T Result => done && error == null ? result : default(T);

        /// <summary>Why it failed, if it did.</summary>
        public Exception Error => done ? error : null;

        public void Complete(T value)
        {
            if (done) throw new InvalidOperationException("this result has already arrived");
            result = value;
            done = true;
        }

        public void Fail(Exception reason)
        {
            if (reason == null) throw new ArgumentNullException(nameof(reason));
            if (done) throw new InvalidOperationException("this result has already arrived");
            error = reason;
            done = true;
        }

        public static Pending<T> Completed(T value)
        {
            var pending = new Pending<T>();
            pending.Complete(value);
            return pending;
        }

        public static Pending<T> Failed(Exception reason)
        {
            var pending = new Pending<T>();
            pending.Fail(reason);
            return pending;
        }

        /// <summary>
        /// Wraps a task. The synchronous <see cref="PageSealer.Seal"/> may block on the
        /// result, which is only safe because a task completes on its own thread.
        /// </summary>
        public static Pending<T> FromTask(Task<T> task)
        {
            if (task == null) throw new ArgumentNullException(nameof(task));
            var pending = new Pending<T>(task);
            task.ContinueWith(t =>
            {
                if (t.IsFaulted) pending.Fail(t.Exception.GetBaseException());
                else if (t.IsCanceled) pending.Fail(new OperationCanceledException("the operation was cancelled"));
                else pending.Complete(t.Result);
            }, TaskContinuationOptions.ExecuteSynchronously);
            return pending;
        }

        internal bool CanBlock => task != null;

        internal void Block()
        {
            try { task.Wait(); }
            catch (AggregateException) { /* reported through Error by the continuation */ }
            // the continuation may still be finishing on the task's thread
            SpinWait.SpinUntil(() => done);
        }
    }
}
