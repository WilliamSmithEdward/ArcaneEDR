using System;
using System.ServiceProcess;

namespace ArcaneEDR
{
    public sealed class ArcaneEdrWindowsService : ServiceBase
    {
        private MonitorEngine engine;

        public ArcaneEdrWindowsService()
        {
            ServiceName = LoadServiceName();
            CanStop = true;
            CanPauseAndContinue = false;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            engine = MonitorComposition.Create(AppDomain.CurrentDomain.BaseDirectory);
            engine.Start();
        }

        protected override void OnStop()
        {
            if (engine != null)
            {
                engine.Stop();
            }
        }

        private static string LoadServiceName()
        {
            try
            {
                MonitorConfig config = MonitorConfig.Load(AppDomain.CurrentDomain.BaseDirectory);
                return String.IsNullOrWhiteSpace(config.ServiceName) ? "ArcaneEDR" : config.ServiceName;
            }
            catch
            {
                return "ArcaneEDR";
            }
        }
    }
}
