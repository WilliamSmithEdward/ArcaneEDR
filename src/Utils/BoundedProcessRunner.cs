using System;
using System.Diagnostics;
using System.Text;

namespace ArcaneEDR
{
    internal sealed class BoundedProcessResult
    {
        public int ExitCode = -1;
        public string StandardOutput = "";
        public string StandardError = "";
        public bool TimedOut;
    }

    internal static class BoundedProcessRunner
    {
        public static BoundedProcessResult Run(ProcessStartInfo startInfo, int timeoutMilliseconds)
        {
            if (startInfo == null) throw new ArgumentNullException("startInfo");

            int timeout = timeoutMilliseconds > 0 ? timeoutMilliseconds : 10000;
            BoundedProcessResult result = new BoundedProcessResult();
            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();
            object stdoutGate = new object();
            object stderrGate = new object();

            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;

            using (Process process = new Process())
            {
                process.StartInfo = startInfo;
                process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs eventArgs)
                {
                    if (eventArgs.Data == null) return;
                    lock (stdoutGate)
                    {
                        stdout.AppendLine(eventArgs.Data);
                    }
                };
                process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs eventArgs)
                {
                    if (eventArgs.Data == null) return;
                    lock (stderrGate)
                    {
                        stderr.AppendLine(eventArgs.Data);
                    }
                };

                if (!process.Start())
                {
                    result.StandardError = "Process did not start.";
                    return result;
                }

                process.BeginOutputReadLine();
                process.BeginErrorReadLine();

                if (!process.WaitForExit(timeout))
                {
                    result.TimedOut = true;
                    try { process.Kill(); }
                    catch (Exception ex) { AppendError(stderr, stderrGate, "Failed to kill timed-out process: " + ex.Message); }
                    try { process.WaitForExit(5000); }
                    catch (Exception ex) { AppendError(stderr, stderrGate, "Failed while waiting after timeout: " + ex.Message); }
                }

                if (process.HasExited)
                {
                    try { process.WaitForExit(); }
                    catch (Exception ex) { AppendError(stderr, stderrGate, "Failed while completing process output read: " + ex.Message); }
                    result.ExitCode = process.ExitCode;
                }
            }

            lock (stdoutGate)
            {
                result.StandardOutput = stdout.ToString();
            }

            lock (stderrGate)
            {
                result.StandardError = stderr.ToString();
            }

            return result;
        }

        private static void AppendError(StringBuilder stderr, object stderrGate, string message)
        {
            lock (stderrGate)
            {
                stderr.AppendLine(message);
            }
        }
    }
}
