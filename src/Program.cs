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

            if (args.Length > 0 &&
                (args[0].Equals("--help", StringComparison.OrdinalIgnoreCase) ||
                 args[0].Equals("-h", StringComparison.OrdinalIgnoreCase) ||
                 args[0].Equals("/?", StringComparison.OrdinalIgnoreCase)))
            {
                PrintUsage();
                return;
            }

            if (args.Length > 0 && args[0].Equals("--test-alert", StringComparison.OrdinalIgnoreCase))
            {
                AlertTestHarness.SendTestAlert(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--test-health", StringComparison.OrdinalIgnoreCase))
            {
                AlertTestHarness.SendHealthTest(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--test-daily-report", StringComparison.OrdinalIgnoreCase))
            {
                AlertTestHarness.SendDailyReportTest(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--preview-daily-report", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = AlertTestHarness.PreviewDailyReport(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--test-ai-analysis", StringComparison.OrdinalIgnoreCase))
            {
                AlertTestHarness.SendAiAnalysisTest(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--preview-ai-payload", StringComparison.OrdinalIgnoreCase))
            {
                AlertTestHarness.PreviewAiPayload(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--incidents", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = IncidentConsole.PrintIncidents(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--timeline", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = IncidentConsole.PrintTimeline(
                    AppDomain.CurrentDomain.BaseDirectory,
                    args.Length > 1 ? args[1] : "");
                return;
            }

            if (args.Length > 0 && args[0].Equals("--alert-volume", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = AlertVolumeConsole.PrintSummary(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--agent-activity", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = AgentActivityConsole.PrintSummary(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--maintenance", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = MaintenanceSessionConsole.Run(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--response-firewall", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = ResponseFirewallConsole.Run(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--policy-preview", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = DetectionPolicyConsole.Preview(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--policy-inspect", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = PolicyInspectConsole.Run(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--support-bundle", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = SupportBundleConsole.Generate(AppDomain.CurrentDomain.BaseDirectory);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--validate-config", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = ConfigValidator.Run(
                    AppDomain.CurrentDomain.BaseDirectory,
                    FirstNonFlagArgument(args, 1),
                    HasFlag(args, "--json"));
                return;
            }

            if (args.Length > 0 && args[0].Equals("--health", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = HealthConsole.Run(AppDomain.CurrentDomain.BaseDirectory, args);
                return;
            }

            if (args.Length > 0 && args[0].Equals("--poll-once", StringComparison.OrdinalIgnoreCase))
            {
                MonitorEngine engine = MonitorComposition.Create(AppDomain.CurrentDomain.BaseDirectory);
                Environment.ExitCode = engine.RunOnce();
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

            if (args.Length > 0)
            {
                Console.Error.WriteLine("Unknown command: " + args[0]);
                Console.Error.WriteLine("Run ArcaneEDR.exe --help for available commands.");
                Environment.ExitCode = 1;
                return;
            }

            ServiceBase.Run(new ArcaneEdrWindowsService());
        }

        private static void PrintUsage()
        {
            Console.WriteLine(VersionInfo.DisplayVersion);
            Console.WriteLine(VersionInfo.RepositoryUrl);
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine("  ArcaneEDR.exe --version");
            Console.WriteLine("  ArcaneEDR.exe --validate-config [config-path]");
            Console.WriteLine("  ArcaneEDR.exe --validate-config [config-path] [--json]");
            Console.WriteLine("  ArcaneEDR.exe --health [--json]");
            Console.WriteLine("  ArcaneEDR.exe --console");
            Console.WriteLine("  ArcaneEDR.exe --poll-once");
            Console.WriteLine("  ArcaneEDR.exe --test-alert [--count <n>]");
            Console.WriteLine("  ArcaneEDR.exe --test-health");
            Console.WriteLine("  ArcaneEDR.exe --test-daily-report");
            Console.WriteLine("  ArcaneEDR.exe --preview-daily-report [--json] [--archive]");
            Console.WriteLine("  ArcaneEDR.exe --test-ai-analysis");
            Console.WriteLine("  ArcaneEDR.exe --preview-ai-payload");
            Console.WriteLine("  ArcaneEDR.exe --alert-volume --last <duration>");
            Console.WriteLine("  ArcaneEDR.exe --alert-volume --last <duration> [--json]");
            Console.WriteLine("  ArcaneEDR.exe --agent-activity --last <duration> [--json]");
            Console.WriteLine("  ArcaneEDR.exe --maintenance start|clear|list [options]");
            Console.WriteLine("  ArcaneEDR.exe --response-firewall list [--json]");
            Console.WriteLine("  ArcaneEDR.exe --response-firewall remove|remove-all");
            Console.WriteLine("  ArcaneEDR.exe --policy-preview --last <duration> [--limit <n>]");
            Console.WriteLine("  ArcaneEDR.exe --policy-preview --sample-rule <rule-id> [sample context options]");
            Console.WriteLine("  ArcaneEDR.exe --policy-preview --sample-alert <json-path>");
            Console.WriteLine("  ArcaneEDR.exe --policy-inspect [--json]");
            Console.WriteLine("  ArcaneEDR.exe --incidents --last <duration> [--json]");
            Console.WriteLine("  ArcaneEDR.exe --timeline <incident-id>");
            Console.WriteLine("  ArcaneEDR.exe --support-bundle");
        }

        private static bool HasFlag(string[] args, string name)
        {
            foreach (string arg in args)
            {
                if (arg.Equals(name, StringComparison.OrdinalIgnoreCase)) return true;
            }

            return false;
        }

        private static string FirstNonFlagArgument(string[] args, int startIndex)
        {
            for (int index = startIndex; index < args.Length; index++)
            {
                if (!args[index].StartsWith("-", StringComparison.Ordinal)) return args[index];
            }

            return "";
        }
    }
}
