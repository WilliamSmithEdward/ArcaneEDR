using System.Text.Json;

namespace ArcaneEDR_Gui.Services;

internal static class GuiJson
{
    public static readonly JsonSerializerOptions IndentedOptions = new JsonSerializerOptions
    {
        WriteIndented = true
    };

    public static readonly JsonSerializerOptions CaseInsensitiveOptions = new JsonSerializerOptions
    {
        PropertyNameCaseInsensitive = true
    };

    public static string Format(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        return Format(document.RootElement);
    }

    public static string Format(JsonElement element)
    {
        return JsonSerializer.Serialize(element, IndentedOptions);
    }

    public static string SerializeIndented<T>(T value)
    {
        return JsonSerializer.Serialize(value, IndentedOptions);
    }
}
