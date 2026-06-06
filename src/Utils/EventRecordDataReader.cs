using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Xml;

namespace ArcaneEDR
{
    internal static class EventRecordDataReader
    {
        public static Dictionary<string, string> ReadEventData(EventRecord record)
        {
            Dictionary<string, string> data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(record.ToXml());

            XmlNodeList nodes = doc.GetElementsByTagName("Data");
            int unnamedIndex = 0;
            foreach (XmlNode node in nodes)
            {
                XmlAttribute name = node.Attributes == null ? null : node.Attributes["Name"];
                string key = name == null || String.IsNullOrWhiteSpace(name.Value)
                    ? "Data" + unnamedIndex.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    : name.Value;

                data[key] = node.InnerText == null ? "" : node.InnerText;
                unnamedIndex++;
            }

            return data;
        }

        public static string Get(Dictionary<string, string> data, string key)
        {
            string value;
            return data.TryGetValue(key, out value) ? value : "";
        }

        public static string FormatDescription(EventRecord record)
        {
            try
            {
                return record.FormatDescription() ?? "";
            }
            catch
            {
                return "";
            }
        }
    }
}
