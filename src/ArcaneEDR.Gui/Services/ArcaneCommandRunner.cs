using System;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ArcaneEDR_Gui.Services;

internal sealed class ArcaneCommandResult
{
    public int ExitCode { get; set; }
    public string StandardOutput { get; set; } = "";
    public string StandardError { get; set; } = "";
    public bool TimedOut { get; set; }

    public string CombinedText()
    {
        if (String.IsNullOrWhiteSpace(StandardError)) return StandardOutput.Trim();
        if (String.IsNullOrWhiteSpace(StandardOutput)) return StandardError.Trim();
        return StandardOutput.Trim() + Environment.NewLine + Environment.NewLine + StandardError.Trim();
    }
}

internal static class ArcaneCommandRunner
{
    public static Task<ArcaneCommandResult> RunAsync(params string[] arguments)
    {
        return RunAsync(TimeSpan.FromSeconds(45), arguments);
    }

    public static async Task<ArcaneCommandResult> RunAsync(TimeSpan timeout, params string[] arguments)
    {
        ArcanePaths paths = ArcanePaths.Discover();
        if (String.IsNullOrWhiteSpace(paths.ServiceExecutable))
        {
            return new ArcaneCommandResult
            {
                ExitCode = 1,
                StandardError = "ArcaneEDR.exe was not found. Build or install Arcane EDR first."
            };
        }

        using Process process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = paths.ServiceExecutable,
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
