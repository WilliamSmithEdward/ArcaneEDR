using System;
using System.Threading;
using System.ServiceProcess;

namespace ArcaneEDR
{
    internal static class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length > 0 &&
                (args[0].Equals("--version", StringComparison.OrdinalIgnoreCase) ||
                 args[0].Equals("-v", StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine(VersionInfo.DisplayVersion);
                Console.WriteLine(VersionInfo.RepositoryUrl);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--test-alert", StringComparison.OrdinalIgnoreCase))
            {
                AlertTestHarness.SendTestAlert(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--test-health", StringComparison.OrdinalIgnoreCase))
            {
                AlertTestHarness.SendHealthTest(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--test-openai-analysis", StringComparison.OrdinalIgnoreCase))
            {
                AlertTestHarness.SendOpenAiAnalysisTest(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--preview-openai-payload", StringComparison.OrdinalIgnoreCase))
            {
                AlertTestHarness.PreviewOpenAiPayload(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--validate-config", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = ConfigValidator.Run(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--console", StringComparison.OrdinalIgnoreCase))
            {
                MonitorEngine engine = MonitorComposition.Create(AppDomain.CurrentDomain.BaseDirectory);
                Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs eventArgs)
                {
                    eventArgs.Cancel = true;
                    engine.Stop();
                };

                engine.Start();
                Console.WriteLine("Arcane EDR running. Press Ctrl+C to stop.");
                while (engine.IsRunning)
                {
                    Thread.Sleep(500);
                }

                return;
            }

            ServiceBase.Run(new ArcaneEdrWindowsService());
        }
    }
}
