namespace ArcaneEDR
{
    internal static class VersionInfo
    {
        public const string ProductName = "Arcane EDR";
        public const string Version = "0.4.0";
        public const string RepositoryUrl = "https://github.com/WilliamSmithEdward/ArcaneEDR";

        public static string DisplayVersion
        {
            get { return ProductName + " " + Version; }
        }
    }
}
