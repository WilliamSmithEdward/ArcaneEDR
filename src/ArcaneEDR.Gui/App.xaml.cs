using System;
using System.Threading.Tasks;
using ArcaneEDR_Gui.Services;
using Microsoft.UI.Xaml;

namespace ArcaneEDR_Gui;

/// <summary>
/// Provides application-specific behavior to supplement the default Application class.
/// </summary>
public partial class App : Application
{
    private MainWindow? _window;
    private TrayIconController? _trayIcon;

    /// <summary>
    /// Initializes the singleton application object. This is the first line of authored code
    /// executed, and as such is the logical equivalent of main() or WinMain().
    /// </summary>
    public App()
    {
        InitializeComponent();
        UnhandledException += App_UnhandledException;
        AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
        TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
    }

    /// <summary>
    /// Invoked when the application is launched.
    /// </summary>
    /// <param name="args">Details about the launch request and process.</param>
    protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs args)
    {
        try
        {
            _window = new MainWindow();
            _trayIcon = new TrayIconController(_window);
            _window.ShowAndActivate();
        }
        catch (Exception ex)
        {
            GuiDiagnostics.LogException("launch", ex);
            throw;
        }
    }

    private static void App_UnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs args)
    {
        GuiDiagnostics.LogException("xaml-unhandled", args.Exception);
    }

    private static void CurrentDomain_UnhandledException(object sender, System.UnhandledExceptionEventArgs args)
    {
        GuiDiagnostics.LogUnhandled("appdomain-unhandled", args.ExceptionObject);
    }

    private static void TaskScheduler_UnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs args)
    {
        GuiDiagnostics.LogException("task-unobserved", args.Exception);
        args.SetObserved();
    }
}
