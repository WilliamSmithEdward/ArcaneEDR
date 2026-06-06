namespace ArcaneEDR
{
    internal sealed class CustomDetectionRule
    {
        public string id { get; set; }
        public string title { get; set; }
        public string source { get; set; }
        public int score { get; set; }
        public string recommendation { get; set; }
        public string[] contains_any { get; set; }
        public string[] process_names { get; set; }
    }
}
