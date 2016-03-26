using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using SystemInteract;

namespace IPTables.Net.TestFramework
{
    public class MockIptablesSystemProcess : ISystemProcess
    {
        private ProcessStartInfo _startInfo = new ProcessStartInfo();

        public MockIptablesSystemProcess(StreamReader output = null, StreamReader error = null)
        {
            StandardOutput = output;
            StandardError = error;
        }

        public bool CloseMainWindow()
        {
            return true;
        }

        public void Close()
        {
        }

        public void Refresh()
        {
        }

        public bool Start()
        {
            return true;
        }

        public void Kill()
        {
        }

        public bool WaitForExit(int milliseconds)
        {
            if (StandardOutput == null && StandardError == null)
            {
                return true;
            }

            DateTime tostop = DateTime.Now.AddMilliseconds(milliseconds);
            do
            {
                if ((StandardOutput == null || StandardOutput.EndOfStream) && (StandardError == null || StandardError.EndOfStream))
                {
                    return true;
                }
                Thread.Sleep(100);
            } while (tostop < DateTime.Now);

            return false;
        }

        public void WaitForExit()
        {
        }

        public bool WaitForInputIdle(int milliseconds)
        {
            return true;
        }

        public bool WaitForInputIdle()
        {
            return true;
        }

        public void BeginOutputReadLine()
        {
        }

        public void BeginErrorReadLine()
        {
        }

        public void CancelOutputRead()
        {
            throw new NotImplementedException();
        }

        public void CancelErrorRead()
        {
        }

        public int ExitCode { get; private set; }
        public bool HasExited { get; private set; }
        public DateTime ExitTime { get; private set; }
        public IntPtr Handle { get; private set; }
        public int HandleCount { get; private set; }
        public int Id { get; private set; }
        public string MachineName { get; private set; }
        public IntPtr MainWindowHandle { get; private set; }
        public string MainWindowTitle { get; private set; }
        public string ProcessName { get; private set; }

        public ProcessStartInfo StartInfo
        {
            get { return _startInfo; }
            set { _startInfo = value; }
        }

        public DateTime StartTime { get; private set; }
        public StreamWriter StandardInput { get; private set; }
        public StreamReader StandardOutput { get; private set; }
        public StreamReader StandardError { get; private set; }
        public int WorkingSet { get; private set; }
        public long WorkingSet64 { get; private set; }
        public event EventHandler Disposed;
        public event DataReceivedEventHandler OutputDataReceived;
        public event DataReceivedEventHandler ErrorDataReceived;
        public event EventHandler Exited;
    }
}
