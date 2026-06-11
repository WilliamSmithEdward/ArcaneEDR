using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

namespace ArcaneEDR_Gui.Services;

internal static class ScrollInputRouter
{
    public static void Attach(FrameworkElement root)
    {
        root.AddHandler(
            UIElement.PointerWheelChangedEvent,
            new PointerEventHandler((_, args) => RouteWheel(root, args)),
            true);
    }

    private static void RouteWheel(FrameworkElement root, PointerRoutedEventArgs args)
    {
        if (args.Handled)
        {
            return;
        }

        int delta = args.GetCurrentPoint(root).Properties.MouseWheelDelta;
        if (delta == 0)
        {
            return;
        }

        ScrollViewer? target = FindScrollableAncestor(args.OriginalSource as DependencyObject, delta) ??
            FindScrollableDescendant(root, delta);
        if (target == null)
        {
            return;
        }

        double nextOffset = Clamp(target.VerticalOffset - delta, 0, target.ScrollableHeight);
        if (Math.Abs(nextOffset - target.VerticalOffset) < 0.5)
        {
            return;
        }

        target.ChangeView(null, nextOffset, null, disableAnimation: true);
        args.Handled = true;
    }

    private static ScrollViewer? FindScrollableAncestor(DependencyObject? current, int delta)
    {
        while (current != null)
        {
            if (current is ScrollViewer scrollViewer && CanScroll(scrollViewer, delta))
            {
                return scrollViewer;
            }

            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private static ScrollViewer? FindScrollableDescendant(DependencyObject current, int delta)
    {
        int count = VisualTreeHelper.GetChildrenCount(current);
        for (int index = 0; index < count; index++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(current, index);
            if (child is ScrollViewer scrollViewer && CanScroll(scrollViewer, delta))
            {
                return scrollViewer;
            }

            ScrollViewer? nested = FindScrollableDescendant(child, delta);
            if (nested != null)
            {
                return nested;
            }
        }

        return null;
    }

    private static bool CanScroll(ScrollViewer scrollViewer, int delta)
    {
        if (scrollViewer.ScrollableHeight <= 0)
        {
            return false;
        }

        double nextOffset = Clamp(scrollViewer.VerticalOffset - delta, 0, scrollViewer.ScrollableHeight);
        return Math.Abs(nextOffset - scrollViewer.VerticalOffset) >= 0.5;
    }

    private static double Clamp(double value, double min, double max)
    {
        if (value < min) return min;
        if (value > max) return max;
        return value;
    }
}
