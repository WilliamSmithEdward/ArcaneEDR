// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Services;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace ArcaneEDR_Gui.Pages;

public sealed partial class SettingsPage : Page
{
    public SettingsPage()
    {
        InitializeComponent();
        SettingsPathText.Text = ArcaneStateReader.BuildPathSummary();
    }

    private void ThemeBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (XamlRoot == null || ThemeBox == null) return;

        string selected = (ThemeBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "Default";
        if (selected.Equals("Light", System.StringComparison.OrdinalIgnoreCase))
        {
            RequestedTheme = Microsoft.UI.Xaml.ElementTheme.Light;
        }
        else if (selected.Equals("Dark", System.StringComparison.OrdinalIgnoreCase))
        {
            RequestedTheme = Microsoft.UI.Xaml.ElementTheme.Dark;
        }
        else
        {
            RequestedTheme = Microsoft.UI.Xaml.ElementTheme.Default;
        }
    }
}
