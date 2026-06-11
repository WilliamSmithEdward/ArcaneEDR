using System;
using System.IO;

namespace ArcaneEDR_Gui.Services;

internal static class GuiDiagnostics
{
    private static readonly object SyncRoot = new();

    public static void Log(string area, string message)
    {
        Write(area, message, null);
    }

    public static void LogException(string area, Exception exception)
    {
        Write(area, exception.Message, exception);
    }

    public static void LogUnhandled(string area, object? exceptionObject)
    {
        if (exceptionObject is Exception exception)
        {
            LogException(area, exception);
            return;
        }

        Write(area, exceptionObject?.ToString() ?? "Unknown unhandled exception.", null);
    }

    private static void Write(string area, string message, Exception? exception)
    {
        try
        {
            string directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Arcane EDR");
            Directory.CreateDirectory(directory);

            string path = Path.Combine(directory, "ArcaneEDR.Gui.log");
            string text = DateTimeOffset.Now.ToString("O") + " [" + area + "] " + message + Environment.NewLine;
            if (exception != null)
            {
                text += exception + Environment.NewLine;
            }

            lock (SyncRoot)
            {
                File.AppendAllText(path, text);
            }
        }
        catch
        {
            // Diagnostics must never become a second failure path.
        }
    }
}
