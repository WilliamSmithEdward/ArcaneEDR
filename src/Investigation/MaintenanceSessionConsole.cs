using System;
using System.Collections.Generic;
using System.Globalization;

namespace ArcaneEDR
{
    internal static class MaintenanceSessionConsole
    {
        public static int Run(string baseDirectory, string[] args)
        {
            MonitorConfig config = MonitorConfig.Load(baseDirectory);
            MaintenanceSessionMarkerStore store = new MaintenanceSessionMarkerStore(config, null);
            string action = args != null && args.Length > 1 ? args[1] : "list";

            if (action.Equals("start", StringComparison.OrdinalIgnoreCase))
            {
                if (!config.EnableMaintenanceContext || !config.EnableMaintenanceSessionMarkers)
                {
                    Console.WriteLine("Maintenance session markers are disabled by config.");
                    return 1;
                }

                TimeSpan duration = ParseDurationArg(args, TimeSpan.FromMinutes(config.MaintenanceSessionDefaultMinutes));
                string reason = ParseValue(args, "--reason", ParseValue(args, "--label", "manual"));
                MaintenanceSessionMarker marker = store.Start(duration, reason, "cli");
                Console.WriteLine("Maintenance session started.");
                Console.WriteLine("Reason=" + marker.Reason);
                Console.WriteLine("StartUtc=" + UtcTimestamp.Format(marker.StartUtc));
                Console.WriteLine("EndUtc=" + UtcTimestamp.Format(marker.EndUtc));
                Console.WriteLine("DurationMinutes=" + marker.DurationMinutes.ToString(CultureInfo.InvariantCulture));
                return 0;
            }

            if (action.Equals("clear", StringComparison.OrdinalIgnoreCase))
            {
                string reason = ParseValue(args, "--reason", "manual-clear");
                MaintenanceSessionMarker marker = store.Clear(reason, "cli");
                Console.WriteLine("Maintenance session cleared.");
                Console.WriteLine("Reason=" + marker.Reason);
                Console.WriteLine("ClearedUtc=" + UtcTimestamp.Format(marker.TimestampUtc));
                return 0;
            }

            if (action.Equals("list", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("status", StringComparison.OrdinalIgnoreCase))
            {
                PrintStatus(config, store, args);
                return 0;
            }

            PrintUsage();
            return 1;
        }

        private static void PrintStatus(MonitorConfig config, MaintenanceSessionMarkerStore store, string[] args)
        {
            MaintenanceSessionMarker active = store.FindActive(DateTime.UtcNow);
            Console.WriteLine("MaintenanceSessionMarkersEnabled=" + (config.EnableMaintenanceContext && config.EnableMaintenanceSessionMarkers));
            if (active == null)
            {
                Console.WriteLine("Active=false");
            }
            else
            {
                Console.WriteLine("Active=true Reason=" + active.Reason + " EndUtc=" + UtcTimestamp.Format(active.EndUtc));
            }

            TimeSpan lookback = InvestigationConsoleOptions.ParseLookback(args, TimeSpan.FromHours(24));
            List<MaintenanceSessionMarker> recent = store.Recent(lookback);
            Console.WriteLine("RecentRecords=" + recent.Count.ToString(CultureInfo.InvariantCulture));
            foreach (MaintenanceSessionMarker marker in recent)
            {
                Console.WriteLine("  " + UtcTimestamp.Format(marker.TimestampUtc) +
                    " action=" + (marker.Cleared ? "clear" : "start") +
                    " reason=" + marker.Reason +
                    " start=" + UtcTimestamp.Format(marker.StartUtc) +
                    " end=" + UtcTimestamp.Format(marker.EndUtc) +
                    " duration_minutes=" + marker.DurationMinutes.ToString(CultureInfo.InvariantCulture));
            }
        }

        private static TimeSpan ParseDurationArg(string[] args, TimeSpan fallback)
        {
            string duration = ParseValue(args, "--duration", "");
            if (!String.IsNullOrWhiteSpace(duration))
            {
                TimeSpan parsed;
                if (InvestigationConsoleOptions.TryParseDuration(duration, out parsed)) return parsed;
            }

            string minutes = ParseValue(args, "--minutes", "");
            int parsedMinutes;
            if (Int32.TryParse(minutes, out parsedMinutes) && parsedMinutes > 0)
            {
                return TimeSpan.FromMinutes(parsedMinutes);
            }

            return fallback;
        }

        private static string ParseValue(string[] args, string name, string fallback)
        {
            for (int index = 0; args != null && index < args.Length - 1; index++)
            {
                if (args[index].Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return args[index + 1];
                }
            }

            return fallback;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  ArcaneEDR.exe --maintenance start [--duration <duration>|--minutes <n>] [--reason <label>]");
            Console.WriteLine("  ArcaneEDR.exe --maintenance clear [--reason <label>]");
            Console.WriteLine("  ArcaneEDR.exe --maintenance list [--last <duration>]");
        }
    }
}
