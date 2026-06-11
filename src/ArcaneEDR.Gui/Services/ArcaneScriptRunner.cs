using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ArcaneEDR_Gui.Services;

internal static class ArcaneScriptRunner
{
    public static Task<ArcaneCommandResult> RunScriptAsync(string scriptName, params string[] arguments)
    {
        return RunScriptAsync(TimeSpan.FromMinutes(3), scriptName, arguments);
    }

    public static async Task<ArcaneCommandResult> RunScriptAsync(TimeSpan timeout, string scriptName, params string[] arguments)
    {
        ArcanePaths paths = ArcanePaths.Discover();
        string script = Path.Combine(paths.ProductRoot, "scripts", scriptName);
        if (!File.Exists(script))
        {
            return new ArcaneCommandResult
            {
                ExitCode = 1,
                StandardError = "Script not found: " + script
            };
        }

        using Process process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = script,
            WorkingDirectory = paths.ProductRoot,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        StringBuilder stdout = new StringBuilder();
        StringBuilder stderr = new StringBuilder();
        process.OutputDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data != null) stdout.AppendLine(eventArgs.Data);
        };
        process.ErrorDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data != null) stderr.AppendLine(eventArgs.Data);
        };

        try
        {
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using CancellationTokenSource cts = new CancellationTokenSource(timeout);
            try
            {
                await process.WaitForExitAsync(cts.Token);
                return new ArcaneCommandResult
                {
                    ExitCode = process.ExitCode,
                    StandardOutput = stdout.ToString(),
                    StandardError = stderr.ToString()
                };
            }
            catch (OperationCanceledException)
            {
                TryKill(process);
                return new ArcaneCommandResult
                {
                    ExitCode = 124,
                    StandardOutput = stdout.ToString(),
                    StandardError = stderr.ToString(),
                    TimedOut = true
                };
            }
        }
        catch (Exception ex)
        {
            return new ArcaneCommandResult
            {
                ExitCode = 1,
                StandardError = ex.Message
            };
        }
    }

    public static void OpenPath(string path)
    {
        if (String.IsNullOrWhiteSpace(path)) return;

        string target = File.Exists(path) || Directory.Exists(path)
            ? path
            : Path.GetDirectoryName(path) ?? path;

        if (String.IsNullOrWhiteSpace(target) || !Directory.Exists(target) && !File.Exists(target)) return;

        Process.Start(new ProcessStartInfo
        {
            FileName = target,
            UseShellExecute = true
        });
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(true);
        }
        catch
        {
        }
    }
}
