using System;

namespace ArcaneEDR
{
    internal static class EventLogRecordState
    {
        public static bool IsLikelyReset(long recordId, DateTime recordTimestampUtc, long lastRecordId, DateTime lastRecordTimestampUtc)
        {
            return lastRecordId > 0 &&
                recordId > 0 &&
                recordId <= lastRecordId &&
                lastRecordTimestampUtc != DateTime.MinValue &&
                recordTimestampUtc != DateTime.MinValue &&
                recordTimestampUtc > lastRecordTimestampUtc.AddMinutes(1.0);
        }
    }
}
