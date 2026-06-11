using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ArcaneEDR_Gui.Pages;
using WinRT.Interop;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace ArcaneEDR_Gui;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        ApplyWindowIcon();
        NavFrame.Navigate(typeof(HomePage));
    }

    private void ApplyWindowIcon()
    {
        var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (!File.Exists(iconPath))
        {
            return;
        }

        var windowHandle = WindowNative.GetWindowHandle(this);
        var windowId = Win32Interop.GetWindowIdFromWindow(windowHandle);
        var appWindow = AppWindow.GetFromWindowId(windowId);
        appWindow.SetIcon(iconPath);
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            NavFrame.Navigate(typeof(SettingsPage));
        }
        else if (args.SelectedItem is NavigationViewItem item)
        {
            switch (item.Tag)
            {
                case "home":
                    NavFrame.Navigate(typeof(HomePage));
                    break;
                case "alerts":
                    NavFrame.Navigate(typeof(AlertsPage));
                    break;
                case "policy":
                    NavFrame.Navigate(typeof(PolicyPage));
                    break;
                case "reports":
                    NavFrame.Navigate(typeof(ReportsPage));
                    break;
                case "configuration":
                    NavFrame.Navigate(typeof(ConfigurationPage));
                    break;
                case "maintenance":
                    NavFrame.Navigate(typeof(MaintenancePage));
                    break;
                case "about":
                    NavFrame.Navigate(typeof(AboutPage));
                    break;
                default:
                    throw new InvalidOperationException($"Unknown navigation item tag: {item.Tag}");
            }
        }
    }
}
