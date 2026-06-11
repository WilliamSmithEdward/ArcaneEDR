using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ArcaneEDR
{
    internal sealed class WmiProcessEnricher : IProcessEnricher
    {
        private readonly FileLogger logger;
        private readonly Dictionary<string, string> hashCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> signerCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public WmiProcessEnricher(FileLogger logger)
        {
            this.logger = logger;
        }

        public Dictionary<int, ProcessInfo> CaptureProcesses()
        {
            Dictionary<int, ProcessInfo> processes = new Dictionary<int, ProcessInfo>();

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId,CreationDate,SessionId FROM Win32_Process"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        ProcessInfo process = ReadProcess(obj);
                        if (process.ProcessId > 0)
                        {
                            processes[process.ProcessId] = process;
                        }
                    }
                }

                foreach (ProcessInfo process in processes.Values)
                {
                    ProcessInfo parent;
                    if (processes.TryGetValue(process.ParentProcessId, out parent))
                    {
                        process.ParentProcessName = parent.ProcessName;
                        process.ParentExecutablePath = parent.ExecutablePath;
                        process.ParentCommandLine = parent.CommandLine;
                    }
                }
            }
            catch (Exception ex)
            {
                logger.Warn("Process enrichment failed: " + ex.Message);
            }

            return processes;
        }

        private ProcessInfo ReadProcess(ManagementObject obj)
        {
            ProcessInfo process = new ProcessInfo();
            process.ProcessId = WmiFields.ReadInt(obj, "ProcessId");
            process.ProcessName = WmiFields.ReadString(obj, "Name");
            process.ExecutablePath = WmiFields.ReadString(obj, "ExecutablePath");
            process.CommandLine = WmiFields.ReadString(obj, "CommandLine");
            process.ParentProcessId = WmiFields.ReadInt(obj, "ParentProcessId");
            process.SessionId = WmiFields.ReadInt(obj, "SessionId");
            process.StartTimeUtc = ReadWmiDate(obj, "CreationDate");
            process.User = ReadOwner(obj);

            if (!String.IsNullOrWhiteSpace(process.ExecutablePath) && File.Exists(process.ExecutablePath))
            {
                process.Sha256 = GetSha256(process.ExecutablePath);
                process.Signer = GetSigner(process.ExecutablePath);
            }

            return process;
        }

        private static DateTime? ReadWmiDate(ManagementObject obj, string name)
        {
            string value = WmiFields.ReadString(obj, name);
            if (String.IsNullOrWhiteSpace(value)) return null;

            try
            {
                return ManagementDateTimeConverter.ToDateTime(value).ToUniversalTime();
            }
            catch
            {
                return null;
            }
        }

        private static string ReadOwner(ManagementObject obj)
        {
            try
            {
                object[] args = new object[] { "", "" };
                uint result = (uint)obj.InvokeMethod("GetOwner", args);
                if (result != 0) return "";

                string user = args[0] == null ? "" : args[0].ToString();
                string domain = args[1] == null ? "" : args[1].ToString();
                if (String.IsNullOrWhiteSpace(domain)) return user;
                return domain + "\\" + user;
            }
            catch
            {
                return "";
            }
        }

        private string GetSha256(string path)
        {
            string cached;
            if (hashCache.TryGetValue(path, out cached)) return cached;

            try
            {
                using (FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(stream);
                    string value = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    hashCache[path] = value;
                    return value;
                }
            }
            catch (Exception ex)
            {
                string value = "hash-error:" + ex.GetType().Name;
                hashCache[path] = value;
                return value;
            }
        }

        private string GetSigner(string path)
        {
            string cached;
            if (signerCache.TryGetValue(path, out cached)) return cached;

            try
            {
                X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
                string value = certificate == null ? "" : certificate.Subject;
                signerCache[path] = value;
                return value;
            }
            catch
            {
                signerCache[path] = "";
                return "";
            }
        }
    }
}
