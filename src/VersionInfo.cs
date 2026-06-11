using System.Reflection;

[assembly: AssemblyTitle("Arcane EDR")]
[assembly: AssemblyProduct("Arcane EDR")]
[assembly: AssemblyCompany("Arcane EDR")]
[assembly: AssemblyVersion("0.8.9.0")]
[assembly: AssemblyFileVersion("0.8.9.0")]
[assembly: AssemblyInformationalVersion("0.8.9")]

namespace ArcaneEDR
{
    internal static class VersionInfo
    {
        public const string ProductName = "Arcane EDR";
        public const string Version = "0.8.9";
        public const string RepositoryUrl = "https://github.com/WilliamSmithEdward/ArcaneEDR";

        public static string DisplayVersion
        {
            get { return ProductName + " " + Version; }
        }
    }
}
