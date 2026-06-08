namespace ArcaneEDR
{
    internal static class AiAnalysisPrompts
    {
        public static string CompactLogPrompt(string compactLogPayload)
        {
            return "You are a security analyst reviewing compact Windows host monitor logs. " +
                "Decide whether this sample is alert-worthy beyond routine noise. " +
                "Return only compact JSON with keys: alertable boolean, score integer 0-100, title string, summary string, recommended_action string. " +
                "Be conservative: alertable=true only for likely compromise, RAT behavior, C2, suspicious persistence, repeated failures, or meaningful degradation. " +
                "If baseline_learning_mode=True, treat service restarts, validation, build/publish/install scripts, ACL hardening, and monitor configuration changes as likely maintenance unless high-confidence malicious indicators remain after filtering. " +
                "Keep summary under 80 words and recommended_action under 50 words.\n\n" +
                compactLogPayload;
        }

        public static string DailyReportPrompt(string dailyReportPayload)
        {
            return "You are a cautious security analyst writing the AI review section of a daily Arcane EDR host-security report. " +
                "The recipient's main question is: is compromise confirmed, is review recommended, or are there no immediate findings from the available evidence? " +
                "Review the redacted aggregate 24-hour report payload and make a high-level, human-readable judgment. " +
                "Do not invent source-event fields such as paths, IPs, users, domains, or command lines because the payload intentionally omits them. " +
                "Do not assume compromise from alert volume alone. Volume can reflect baseline learning, repeated low-score rules, agent activity, maintenance, or limited aggregate context. " +
                "Explicitly account for false-positive potential, baseline_learning_mode, maintenance_context, automation or agent context, collector gaps, and whether full source-event context is absent. " +
                "Use phrases like 'no confirmed compromise' or 'needs review' when evidence is suggestive but not conclusive. " +
                "Return only compact JSON with keys: alertable boolean, score integer 0-100, title string, summary string, recommended_action string. " +
                "Use alertable=true only when high-confidence signals justify priority review after considering plausible false positives; do not set alertable=true for routine baseline noise. " +
                "Keep the title plain and verdict-like. Keep summary under 120 words and recommended_action under 60 words.\n\n" +
                dailyReportPayload;
        }
    }
}
