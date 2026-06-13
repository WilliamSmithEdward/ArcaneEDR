using System;
using System.Collections.Generic;
using System.IO;

namespace ArcaneEDR_Gui.Services;

internal sealed class ArcanePaths
{
    public string ProductRoot { get; private set; } = "";
    public string ServiceExecutable { get; private set; } = "";
    public string ConfigFile { get; private set; } = "";
    public string DeploymentConfigFile { get; private set; } = "";
    public string PolicyFile { get; private set; } = "";
    public string LogDirectory { get; private set; } = "";
    public bool UsesExampleConfig { get; private set; }

    public static ArcanePaths Discover()
    {
        foreach (string root in CandidateRoots())
        {
            string config = Existing(
                Path.Combine(root, "config", "ArcaneEDR.config"),
                Path.Combine(root, "config", "ArcaneEDR.example.config"));
            string exe = Existing(
                Path.Combine(root, "bin", "ArcaneEDR.exe"),
                Path.Combine(root, "ArcaneEDR.exe"),
                Path.Combine(root, "bin", "ArcaneEDR.check.exe"));

            if (String.IsNullOrWhiteSpace(config) && String.IsNullOrWhiteSpace(exe))
            {
                continue;
            }

            string configDirectory = String.IsNullOrWhiteSpace(config)
                ? Path.Combine(root, "config")
                : Path.GetDirectoryName(config) ?? root;
            string logDirectory = ResolvePath(
                configDirectory,
                ReadConfigValue(config, "LogDirectory", Path.Combine(root, "logs")));
            string policyFile = ResolvePath(
                configDirectory,
                ReadConfigValue(config, "PolicyFile", "arcane-policy.example.json"));

            return new ArcanePaths
            {
                ProductRoot = root,
                ServiceExecutable = exe,
                ConfigFile = config,
                DeploymentConfigFile = Existing(
                    Path.Combine(root, "config", "Deployment.config"),
                    Path.Combine(root, "config", "Deployment.example.config")),
                PolicyFile = policyFile,
                LogDirectory = logDirectory,
                UsesExampleConfig = config.EndsWith(".example.config", StringComparison.OrdinalIgnoreCase)
            };
        }

        string fallback = AppContext.BaseDirectory;
        return new ArcanePaths
        {
            ProductRoot = fallback,
            LogDirectory = Path.Combine(fallback, "logs")
        };
    }

    public string HealthStateFile()
    {
        return Path.Combine(LogDirectory, "ArcaneServiceHealth.state");
    }

    public string AlertsFile()
    {
        return Path.Combine(LogDirectory, "ArcaneAlerts.jsonl");
    }

    private static IEnumerable<string> CandidateRoots()
    {
        string current = AppContext.BaseDirectory;
        for (int depth = 0; depth < 10 && !String.IsNullOrWhiteSpace(current); depth++)
        {
            yield return current;
            string? parent = Directory.GetParent(current)?.FullName;
            if (String.IsNullOrWhiteSpace(parent) ||
                parent.Equals(current, StringComparison.OrdinalIgnoreCase))
            {
                break;
            }

            current = parent;
        }

        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!String.IsNullOrWhiteSpace(programFiles))
        {
            yield return Path.Combine(programFiles, "Arcane EDR");
        }
    }

    private static string Existing(params string[] paths)
    {
        foreach (string path in paths)
        {
            if (!String.IsNullOrWhiteSpace(path) && File.Exists(path)) return path;
        }

        return "";
    }

    private static string ReadConfigValue(string path, string key, string fallback)
    {
        if (String.IsNullOrWhiteSpace(path) || !File.Exists(path)) return fallback;

        foreach (string rawLine in File.ReadAllLines(path))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) continue;

            int equals = line.IndexOf('=');
            if (equals <= 0) continue;

            string name = line.Substring(0, equals).Trim();
            if (name.Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                return line.Substring(equals + 1).Trim();
            }
        }

        return fallback;
    }

    private static string ResolvePath(string baseDirectory, string value)
    {
        if (String.IsNullOrWhiteSpace(value)) return "";
        string expanded = Environment.ExpandEnvironmentVariables(value.Trim());
        if (Path.IsPathRooted(expanded)) return expanded;
        return Path.GetFullPath(Path.Combine(baseDirectory, expanded));
    }
}
