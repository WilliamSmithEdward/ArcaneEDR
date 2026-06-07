using System;

namespace ArcaneEDR
{
    internal static class SupportBundleConsole
    {
        public static int Generate(string baseDirectory)
        {
            try
            {
                MonitorConfig config = MonitorConfig.Load(baseDirectory);
                SupportBundleGenerator generator = new SupportBundleGenerator(config, baseDirectory);
                string path = generator.Generate();
                Console.WriteLine("Support bundle created:");
                Console.WriteLine(path);
                Console.WriteLine("Review before sharing. The bundle is redacted and bounded, but local context can still be sensitive.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Support bundle failed: " + ex.Message);
                return 1;
            }
        }
    }
}
