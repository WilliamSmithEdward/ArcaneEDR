using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using Microsoft.Win32;

namespace ArcaneEDR
{
    internal sealed class PersistenceInventoryCollector : IHostTelemetryCollector
    {
        private readonly MonitorConfig config;
        private readonly FileLogger logger;
        private DateTime lastScanUtc = DateTime.MinValue;
        private bool warnedServices;
        private bool warnedTasks;

        public PersistenceInventoryCollector(MonitorConfig config, FileLogger logger)
        {
            this.config = config;
            this.logger = logger;
        }

        public HostTelemetry Capture()
        {
            HostTelemetry telemetry = new HostTelemetry();
            if (!config.EnablePersistenceInventory)
            {
                return telemetry;
            }

            DateTime now = DateTime.UtcNow;
            if (lastScanUtc != DateTime.MinValue &&
                (now - lastScanUtc).TotalMinutes < Math.Max(1, config.PersistenceInventoryIntervalMinutes))
            {
                return telemetry;
            }

            lastScanUtc = now;
            ScanRegistryRunKeys(telemetry);
            ScanStartupFolders(telemetry);
            ScanServices(telemetry);
            ScanScheduledTasks(telemetry);
            return telemetry;
        }

        private void ScanRegistryRunKeys(HostTelemetry telemetry)
        {
            ScanRegistryRunKey(Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\Run", telemetry);
            ScanRegistryRunKey(Registry.LocalMachine, "HKLM", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", telemetry);
            ScanRegistryRunKey(Registry.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", telemetry);
            ScanRegistryRunKey(Registry.LocalMachine, "HKLM", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", telemetry);
            ScanRegistryRunKey(Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\Run", telemetry);
            ScanRegistryRunKey(Registry.CurrentUser, "HKCU", @"Software\Microsoft\Windows\CurrentVersion\RunOnce", telemetry);
        }

        private void ScanRegistryRunKey(RegistryKey root, string rootName, string subKey, HostTelemetry telemetry)
        {
            try
            {
                using (RegistryKey key = root.OpenSubKey(subKey))
                {
                    if (key == null) return;

                    foreach (string valueName in key.GetValueNames())
                    {
                        object value = key.GetValue(valueName);
                        string command = value == null ? "" : value.ToString();
                        telemetry.PersistenceItems.Add(Create("RegistryRun", valueName, rootName + "\\" + subKey, command, "registry"));
                    }
                }
            }
            catch (Exception ex)
            {
                logger.Warn("Persistence registry scan failed for " + rootName + "\\" + subKey + ": " + ex.Message);
            }
        }

        private void ScanStartupFolders(HostTelemetry telemetry)
        {
            ScanStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "CommonStartup", telemetry);
            ScanStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "UserStartup", telemetry);
        }

        private void ScanStartupFolder(string folder, string source, HostTelemetry telemetry)
        {
            if (String.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) return;

            foreach (string file in Directory.GetFiles(folder))
            {
                if (Path.GetFileName(file).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                telemetry.PersistenceItems.Add(Create("StartupFolder", Path.GetFileName(file), file, file, source));
            }
        }

        private void ScanServices(HostTelemetry telemetry)
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT Name,DisplayName,PathName,StartMode,State FROM Win32_Service"))
                {
                    foreach (ManagementObject service in searcher.Get())
                    {
                        string name = ReadString(service, "Name");
                        string display = ReadString(service, "DisplayName");
                        string path = ReadString(service, "PathName");
                        string startMode = ReadString(service, "StartMode");
                        if (!startMode.Equals("Auto", StringComparison.OrdinalIgnoreCase) &&
                            !startMode.Equals("Automatic", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }

                        telemetry.PersistenceItems.Add(Create("Service", name, display, path, "Win32_Service"));
                    }
                }
            }
            catch (Exception ex)
            {
                if (!warnedServices)
                {
                    logger.Warn("Persistence service scan failed: " + ex.Message);
                    warnedServices = true;
                }
            }
        }

        private void ScanScheduledTasks(HostTelemetry telemetry)
        {
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "schtasks.exe";
                startInfo.Arguments = "/Query /FO CSV /V";
                startInfo.UseShellExecute = false;
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;
                startInfo.CreateNoWindow = true;

                BoundedProcessResult result = BoundedProcessRunner.Run(startInfo, 10000);
                if (result.TimedOut)
                {
                    WarnTasksOnce("Persistence scheduled task scan timed out.");
                    return;
                }

                if (!String.IsNullOrWhiteSpace(result.StandardError))
                {
                    WarnTasksOnce("Persistence scheduled task scan stderr: " + result.StandardError.Trim());
                }

                if (result.ExitCode != 0)
                {
                    WarnTasksOnce("Persistence scheduled task scan exited with code " + result.ExitCode.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".");
                }

                ParseScheduledTaskCsv(result.StandardOutput, telemetry);
            }
            catch (Exception ex)
            {
                WarnTasksOnce("Persistence scheduled task scan failed: " + ex.Message);
            }
        }

        private void WarnTasksOnce(string message)
        {
            if (warnedTasks) return;
            if (logger != null) logger.Warn(message);
            warnedTasks = true;
        }

        private void ParseScheduledTaskCsv(string output, HostTelemetry telemetry)
        {
            if (String.IsNullOrWhiteSpace(output)) return;

            string[] lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length < 2) return;

            List<string> headers = ParseCsvLine(lines[0]);
            int taskNameIndex = IndexOf(headers, "TaskName");
            int taskRunIndex = IndexOf(headers, "Task To Run");
            int statusIndex = IndexOf(headers, "Status");

            for (int i = 1; i < lines.Length; i++)
            {
                List<string> values = ParseCsvLine(lines[i]);
                string taskName = Get(values, taskNameIndex);
                string taskRun = Get(values, taskRunIndex);
                string status = Get(values, statusIndex);
                if (String.IsNullOrWhiteSpace(taskName) || String.IsNullOrWhiteSpace(taskRun)) continue;
                if (taskRun.Equals("N/A", StringComparison.OrdinalIgnoreCase)) continue;

                telemetry.PersistenceItems.Add(Create("ScheduledTask", taskName, taskName, taskRun, "schtasks status=" + status));
            }
        }

        private static List<string> ParseCsvLine(string line)
        {
            List<string> values = new List<string>();
            bool quoted = false;
            System.Text.StringBuilder current = new System.Text.StringBuilder();

            for (int i = 0; i < line.Length; i++)
            {
                char ch = line[i];
                if (ch == '"')
                {
                    if (quoted && i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        quoted = !quoted;
                    }
                }
                else if (ch == ',' && !quoted)
                {
                    values.Add(current.ToString());
                    current.Length = 0;
                }
                else
                {
                    current.Append(ch);
                }
            }

            values.Add(current.ToString());
            return values;
        }

        private static int IndexOf(List<string> headers, string name)
        {
            for (int i = 0; i < headers.Count; i++)
            {
                if (headers[i].Equals(name, StringComparison.OrdinalIgnoreCase)) return i;
            }

            return -1;
        }

        private static string Get(List<string> values, int index)
        {
            return index >= 0 && index < values.Count ? values[index] : "";
        }

        private static string ReadString(ManagementObject obj, string name)
        {
            object value = obj[name];
            return value == null ? "" : value.ToString();
        }

        private PersistenceItem Create(string type, string name, string path, string command, string source)
        {
            PersistenceItem item = new PersistenceItem();
            item.Type = type;
            item.Name = name ?? "";
            item.Path = path ?? "";
            item.Command = command ?? "";
            item.Source = source ?? "";
            item.Signer = PersistenceTrust.Evaluate(config, item.Name, item.Path, item.Command, "").Signer;
            item.ObservedUtc = DateTime.UtcNow;
            return item;
        }
    }
}
