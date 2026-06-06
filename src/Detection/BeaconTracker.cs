using System;
using System.Collections.Generic;

namespace ArcaneEDR
{
    internal sealed class BeaconTracker
    {
        private readonly Dictionary<string, List<DateTime>> observations = new Dictionary<string, List<DateTime>>(StringComparer.OrdinalIgnoreCase);

        public BeaconResult RecordAndEvaluate(
            string flowKey,
            DateTime timestampUtc,
            int minimumSamples,
            int maximumAverageIntervalSeconds,
            double maximumJitterRatio)
        {
            List<DateTime> times;
            if (!observations.TryGetValue(flowKey, out times))
            {
                times = new List<DateTime>();
                observations[flowKey] = times;
            }

            times.Add(timestampUtc);
            Trim(times, Math.Max(minimumSamples + 4, 12));

            if (times.Count < minimumSamples)
            {
                return BeaconResult.NotDetected;
            }

            List<DateTime> sample = times.GetRange(times.Count - minimumSamples, minimumSamples);
            List<double> intervals = new List<double>();
            for (int i = 1; i < sample.Count; i++)
            {
                intervals.Add((sample[i] - sample[i - 1]).TotalSeconds);
            }

            double average = Average(intervals);
            if (average <= 0 || average > maximumAverageIntervalSeconds)
            {
                return BeaconResult.NotDetected;
            }

            double jitterRatio = StandardDeviation(intervals, average) / average;
            if (jitterRatio > maximumJitterRatio)
            {
                return BeaconResult.NotDetected;
            }

            return new BeaconResult(true, average, jitterRatio, sample.Count);
        }

        private static void Trim(List<DateTime> times, int maxItems)
        {
            while (times.Count > maxItems)
            {
                times.RemoveAt(0);
            }
        }

        private static double Average(List<double> values)
        {
            double total = 0;
            foreach (double value in values)
            {
                total += value;
            }

            return total / values.Count;
        }

        private static double StandardDeviation(List<double> values, double average)
        {
            double total = 0;
            foreach (double value in values)
            {
                double delta = value - average;
                total += delta * delta;
            }

            return Math.Sqrt(total / values.Count);
        }
    }

    internal sealed class BeaconResult
    {
        public static readonly BeaconResult NotDetected = new BeaconResult(false, 0, 0, 0);

        public BeaconResult(bool detected, double averageIntervalSeconds, double jitterRatio, int samples)
        {
            Detected = detected;
            AverageIntervalSeconds = averageIntervalSeconds;
            JitterRatio = jitterRatio;
            Samples = samples;
        }

        public bool Detected { get; private set; }
        public double AverageIntervalSeconds { get; private set; }
        public double JitterRatio { get; private set; }
        public int Samples { get; private set; }
    }
}
