using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace ArcaneEDR_Gui.Services;

internal static class GuiHelp
{
    public static async Task ShowAsync(XamlRoot xamlRoot, string title, string content)
    {
        ContentDialog dialog = new ContentDialog
        {
            XamlRoot = xamlRoot,
            Title = title,
            Content = Body(content),
            CloseButtonText = "Got it",
            DefaultButton = ContentDialogButton.Close
        };

        await dialog.ShowAsync();
    }

    public static async Task<bool> ConfirmRiskAsync(
        XamlRoot xamlRoot,
        string title,
        string content,
        string primaryText)
    {
        ContentDialog dialog = new ContentDialog
        {
            XamlRoot = xamlRoot,
            Title = title,
            Content = Body(content),
            PrimaryButtonText = primaryText,
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close
        };

        ContentDialogResult result = await dialog.ShowAsync();
        return result == ContentDialogResult.Primary;
    }

    private static TextBlock Body(string content)
    {
        return new TextBlock
        {
            Text = content,
            TextWrapping = TextWrapping.WrapWholeWords,
            IsTextSelectionEnabled = true,
            MaxWidth = 620
        };
    }
}
