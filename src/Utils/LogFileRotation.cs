using System;
using System.Globalization;
using System.IO;

namespace ArcaneEDR
{
    internal static class LogFileRotation
    {
        public static void RotateIfNeeded(string path, long maxBytes)
        {
            try
            {
                FileInfo file = new FileInfo(path);
                if (!file.Exists || file.Length < maxBytes) return;

                string rotated = path + "." + DateTime.UtcNow.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + ".old";
                File.Move(path, rotated);
            }
            catch
            {
            }
        }
    }
}
