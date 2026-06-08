namespace ArcaneEDR
{
    internal sealed class AiAnalysisProviderSettings
    {
        public string ProviderName;
        public string ProviderType;
        public string Model;
        public string ApiUrl;
        public string ApiKeyEnvironmentVariable;
        public string AuthHeaderName;
        public string AuthHeaderPrefix;
        public bool AuthHeaderPrefixConfigured;
        public string VersionHeaderName;
        public string VersionHeaderValue;

        public string DisplayName
        {
            get { return string.IsNullOrWhiteSpace(ProviderName) ? ProviderType : ProviderName; }
        }
    }
}
