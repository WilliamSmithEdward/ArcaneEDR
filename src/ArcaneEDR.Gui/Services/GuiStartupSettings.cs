using System;
using System.IO;
using System.Text.Json;
using Microsoft.Win32;

namespace ArcaneEDR_Gui.Services;

internal sealed class GuiUserSettings
{
    public bool StartOnWindowsLogin { get; set; } = true;
    public bool StartMinimizedOnWindowsLogin { get; set; } = true;
    public string AlertLookback { get; set; } = "24h";
    public string AlertSeverity { get; set; } = "Any";
    public string AlertCategory { get; set; } = "Any";
    public string AlertSearch { get; set; } = "";
    public bool AlertExternalThresholdOnly { get; set; }
    public string AlertSortColumn { get; set; } = "Time";
    public bool AlertSortAscending { get; set; }
    public double AlertDetailsHeight { get; set; } = 180;
    public bool PolicyHideDisabled { get; set; } = true;
}

internal static class GuiStartupSettings
{
    private const string StartupArgument = "--startup";
    private const string RunValueName = "Arcane EDR GUI";
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string SettingsFileName = "ArcaneEDR.Gui.settings.json";

    public static GuiUserSettings Load()
    {
        try
        {
            string path = SettingsPath();
            if (!File.Exists(path))
            {
                return new GuiUserSettings();
            }

            string json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<GuiUserSettings>(json) ?? new GuiUserSettings();
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("gui-settings-load", ex);
            return new GuiUserSettings();
        }
    }

    public static void SaveAndApply(GuiUserSettings settings)
    {
        Save(settings);
        ApplyStartupRegistration(settings);
    }

    public static void Save(GuiUserSettings settings)
    {
        Directory.CreateDirectory(SettingsDirectory());
        File.WriteAllText(SettingsPath(), GuiJson.SerializeIndented(settings));
    }

    public static GuiUserSettings LoadSaveAndApply()
    {
        GuiUserSettings settings = Load();
        if (ShouldApplyStartupRegistrationForCurrentProcess())
        {
            SaveAndApply(settings);
        }
        else
        {
            Save(settings);
        }

        return settings;
    }

    public static bool IsStartupLaunch(string? launchArguments)
    {
        if (ContainsStartupArgument(launchArguments))
        {
            return true;
        }

        foreach (string argument in Environment.GetCommandLineArgs())
        {
            if (IsStartupArgument(argument))
            {
                return true;
            }
        }

        return false;
    }

    public static string BuildStatusText()
    {
        string command = ReadRegisteredCommand();
        string registered = String.IsNullOrWhiteSpace(command) ? "No" : "Yes";
        return "Startup registered: " + registered + Environment.NewLine +
            "Startup command: " + (String.IsNullOrWhiteSpace(command) ? "(none)" : command) + Environment.NewLine +
            "Settings file: " + SettingsPath();
    }

    public static string SettingsPath()
    {
        return Path.Combine(SettingsDirectory(), SettingsFileName);
    }

    private static void ApplyStartupRegistration(GuiUserSettings settings)
    {
        using RegistryKey? runKey = Registry.CurrentUser.CreateSubKey(RunKeyPath);
        if (runKey == null)
        {
            throw new InvalidOperationException("Could not open the current-user Windows Run registry key.");
        }

        if (settings.StartOnWindowsLogin)
        {
            runKey.SetValue(RunValueName, BuildStartupCommand(), RegistryValueKind.String);
        }
        else
        {
            runKey.DeleteValue(RunValueName, throwOnMissingValue: false);
        }
    }

    private static string ReadRegisteredCommand()
    {
        try
        {
            using RegistryKey? runKey = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
            return runKey?.GetValue(RunValueName)?.ToString() ?? "";
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("gui-startup-read", ex);
            return "";
        }
    }

    private static string BuildStartupCommand()
    {
        string executable = Environment.ProcessPath ?? "";
        if (String.IsNullOrWhiteSpace(executable))
        {
            executable = Path.Combine(AppContext.BaseDirectory, "ArcaneEDR.Gui.exe");
        }

        return "\"" + executable + "\" " + StartupArgument;
    }

    private static bool ShouldApplyStartupRegistrationForCurrentProcess()
    {
        string executable = Environment.ProcessPath ?? "";
        if (String.IsNullOrWhiteSpace(executable))
        {
            return true;
        }

        string normalized = Path.GetFullPath(executable).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string programFilesRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Arcane EDR").TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (normalized.StartsWith(programFilesRoot, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static bool ContainsStartupArgument(string? launchArguments)
    {
        if (String.IsNullOrWhiteSpace(launchArguments))
        {
            return false;
        }

        foreach (string argument in launchArguments.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (IsStartupArgument(argument))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsStartupArgument(string argument)
    {
        return argument.Equals(StartupArgument, StringComparison.OrdinalIgnoreCase) ||
            argument.Equals("/startup", StringComparison.OrdinalIgnoreCase);
    }

    private static string SettingsDirectory()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Arcane EDR");
    }
}
