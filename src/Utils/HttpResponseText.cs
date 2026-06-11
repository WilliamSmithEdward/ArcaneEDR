using System.IO;
using System.Net;
using System.Text;

namespace ArcaneEDR
{
    internal static class HttpResponseText
    {
        public static int TimeoutMilliseconds(int timeoutSeconds, int defaultSeconds)
        {
            int seconds = timeoutSeconds <= 0 ? defaultSeconds : timeoutSeconds;
            return seconds * 1000;
        }

        public static string Read(HttpWebResponse response)
        {
            if (response == null) return "";
            using (Stream stream = response.GetResponseStream())
            {
                if (stream == null) return "";
                using (StreamReader reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }
            }
        }

        public static string ReadUtf8(HttpWebResponse response)
        {
            if (response == null) return "";
            using (Stream stream = response.GetResponseStream())
            {
                if (stream == null) return "";
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
                {
                    return reader.ReadToEnd();
                }
            }
        }
    }
}
