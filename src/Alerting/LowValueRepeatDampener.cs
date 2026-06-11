using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class LowValueRepeatDampener
    {
        private readonly MonitorConfig config;
        private readonly Dictionary<string, Queue<DateTime>> sightings = new Dictionary<string, Queue<DateTime>>(StringComparer.OrdinalIgnoreCase);

        public LowValueRepeatDampener(MonitorConfig config)
        {
            this.config = config;
        }

        public bool ShouldDampen(Alert alert)
        {
            if (alert == null || config == null || !config.EnableLowValueRepeatDampening)
            {
                return false;
            }

            if (alert.Score > config.LowValueRepeatDampeningMaximumScore)
            {
                return false;
            }

            if (config.LowValueRepeatDampeningWindowMinutes <= 0 ||
                config.LowValueRepeatDampeningMaxExternalAlertsPerWindow <= 0)
            {
                return false;
            }

            string category = AlertRulePolicy.AlertCategory(alert);
            if (config.LowValueRepeatDampeningCategories.Count == 0 ||
                !config.LowValueRepeatDampeningCategories.Contains(category))
            {
                return false;
            }

            string key = AlertSourceRoot.BuildRepeatKey(alert, category);
            if (String.IsNullOrWhiteSpace(key))
            {
                return false;
            }

            DateTime now = DateTime.UtcNow;
            DateTime cutoff = now.AddMinutes(-config.LowValueRepeatDampeningWindowMinutes);

            Queue<DateTime> queue;
            if (!sightings.TryGetValue(key, out queue))
            {
                queue = new Queue<DateTime>();
                sightings[key] = queue;
            }

            while (queue.Count > 0 && queue.Peek() < cutoff)
            {
                queue.Dequeue();
            }

            queue.Enqueue(now);
            return queue.Count > config.LowValueRepeatDampeningMaxExternalAlertsPerWindow;
        }

    }
}
