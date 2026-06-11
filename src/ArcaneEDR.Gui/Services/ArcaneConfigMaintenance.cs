using System;
using System.IO;

namespace ArcaneEDR_Gui.Services;

internal static class ArcaneConfigMaintenance
{
    public static string ResetLocalConfigToDefaults()
    {
        ArcanePaths paths = ArcanePaths.Discover();
        string configDirectory = Path.GetDirectoryName(paths.ConfigFile) ?? "";
        if (String.IsNullOrWhiteSpace(configDirectory) || !Directory.Exists(configDirectory))
        {
            return "Config directory was not found.";
        }

        string runtimeConfig = Path.Combine(configDirectory, "ArcaneEDR.config");
        string runtimeDeploymentConfig = Path.Combine(configDirectory, "Deployment.config");
        string exampleConfig = Path.Combine(configDirectory, "ArcaneEDR.example.config");
        string exampleDeploymentConfig = Path.Combine(configDirectory, "Deployment.example.config");

        string timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
        string backupDirectory = Path.Combine(configDirectory, "backup-before-reset-" + timestamp);
        Directory.CreateDirectory(backupDirectory);

        BackupIfExists(runtimeConfig, backupDirectory);
        BackupIfExists(runtimeDeploymentConfig, backupDirectory);

        if (!File.Exists(exampleConfig))
        {
            return "ArcaneEDR.example.config was not found. Backups, if any, were written to " + backupDirectory + ".";
        }

        File.Copy(exampleConfig, runtimeConfig, true);
        if (File.Exists(exampleDeploymentConfig))
        {
            File.Copy(exampleDeploymentConfig, runtimeDeploymentConfig, true);
        }

        return "Reset local config to defaults. Backup directory: " + backupDirectory;
    }

    private static void BackupIfExists(string path, string backupDirectory)
    {
        if (!File.Exists(path)) return;
        File.Copy(path, Path.Combine(backupDirectory, Path.GetFileName(path)), true);
    }
}
