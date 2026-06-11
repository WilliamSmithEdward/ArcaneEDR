using System;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

namespace ArcaneEDR_Gui.Controls;

public static class PageScrollBehavior
{
    private const double OffsetTolerance = 2.0;

    public static readonly DependencyProperty UseReliableWheelProperty =
        DependencyProperty.RegisterAttached(
            "UseReliableWheel",
            typeof(bool),
            typeof(PageScrollBehavior),
            new PropertyMetadata(false, OnUseReliableWheelChanged));

    private static readonly PointerEventHandler WheelHandler = HandlePointerWheelChanged;

    private static readonly DependencyProperty HookedContentProperty =
        DependencyProperty.RegisterAttached(
            "HookedContent",
            typeof(UIElement),
            typeof(PageScrollBehavior),
            new PropertyMetadata(null));

    private static readonly DependencyProperty OwnerScrollViewerProperty =
        DependencyProperty.RegisterAttached(
            "OwnerScrollViewer",
            typeof(ScrollViewer),
            typeof(PageScrollBehavior),
            new PropertyMetadata(null));

    public static bool GetUseReliableWheel(DependencyObject element)
    {
        return (bool)element.GetValue(UseReliableWheelProperty);
    }

    public static void SetUseReliableWheel(DependencyObject element, bool value)
    {
        element.SetValue(UseReliableWheelProperty, value);
    }

    private static void OnUseReliableWheelChanged(DependencyObject element, DependencyPropertyChangedEventArgs args)
    {
        if (element is not ScrollViewer scrollViewer)
        {
            return;
        }

        scrollViewer.Loaded -= ScrollViewer_Loaded;
        DetachFromCurrentContent(scrollViewer);

        if (args.NewValue is true)
        {
            scrollViewer.Loaded += ScrollViewer_Loaded;
            AttachToCurrentContent(scrollViewer);
        }
    }

    private static void ScrollViewer_Loaded(object sender, RoutedEventArgs args)
    {
        if (sender is ScrollViewer scrollViewer)
        {
            AttachToCurrentContent(scrollViewer);
        }
    }

    private static void AttachToCurrentContent(ScrollViewer scrollViewer)
    {
        if (scrollViewer.Content is not UIElement content)
        {
            return;
        }

        if (ReferenceEquals(scrollViewer.GetValue(HookedContentProperty), content))
        {
            return;
        }

        DetachFromCurrentContent(scrollViewer);
        EnsureHitTestableContent(content);
        content.SetValue(OwnerScrollViewerProperty, scrollViewer);
        content.AddHandler(UIElement.PointerWheelChangedEvent, WheelHandler, true);
        scrollViewer.SetValue(HookedContentProperty, content);
    }

    private static void DetachFromCurrentContent(ScrollViewer scrollViewer)
    {
        if (scrollViewer.GetValue(HookedContentProperty) is not UIElement content)
        {
            return;
        }

        content.RemoveHandler(UIElement.PointerWheelChangedEvent, WheelHandler);
        content.ClearValue(OwnerScrollViewerProperty);
        scrollViewer.ClearValue(HookedContentProperty);
    }

    private static void HandlePointerWheelChanged(object sender, PointerRoutedEventArgs args)
    {
        if (sender is not DependencyObject hookSource ||
            hookSource.GetValue(OwnerScrollViewerProperty) is not ScrollViewer pageScrollViewer)
        {
            return;
        }

        int delta = args.GetCurrentPoint(pageScrollViewer).Properties.MouseWheelDelta;
        if (delta == 0)
        {
            return;
        }

        if (pageScrollViewer.ScrollableHeight <= 0)
        {
            args.Handled = true;
            return;
        }

        if (!IsAtDirectionalEdge(pageScrollViewer, delta))
        {
            return;
        }

        ScrollViewer? nestedScrollViewer = FindNearestNestedScrollViewer(
            pageScrollViewer,
            args.OriginalSource as DependencyObject);
        if (nestedScrollViewer != null && !IsAtDirectionalEdge(nestedScrollViewer, delta))
        {
            return;
        }

        AbsorbBoundaryWheel(pageScrollViewer, args, delta);
    }

    private static ScrollViewer? FindNearestNestedScrollViewer(ScrollViewer owner, DependencyObject? current)
    {
        while (current != null && current != owner)
        {
            if (current is ScrollViewer scrollViewer)
            {
                return scrollViewer;
            }

            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private static void AbsorbBoundaryWheel(ScrollViewer scrollViewer, PointerRoutedEventArgs args, int delta)
    {
        scrollViewer.CancelDirectManipulations();

        double pinnedOffset = GetDirectionalEdgeOffset(scrollViewer, delta);
        if (Math.Abs(pinnedOffset - scrollViewer.VerticalOffset) >= OffsetTolerance)
        {
            scrollViewer.ChangeView(null, pinnedOffset, null, disableAnimation: true);
        }

        args.Handled = true;
    }

    private static void EnsureHitTestableContent(UIElement content)
    {
        if (content is Panel { Background: null } panel)
        {
            panel.Background = new SolidColorBrush(Colors.Transparent);
        }

        if (content is Border { Background: null } border)
        {
            border.Background = new SolidColorBrush(Colors.Transparent);
        }
    }

    private static bool IsAtDirectionalEdge(ScrollViewer scrollViewer, int delta)
    {
        if (delta > 0)
        {
            return scrollViewer.VerticalOffset <= OffsetTolerance;
        }

        return scrollViewer.ScrollableHeight - scrollViewer.VerticalOffset <= OffsetTolerance;
    }

    private static double GetDirectionalEdgeOffset(ScrollViewer scrollViewer, int delta)
    {
        return delta > 0 ? 0 : scrollViewer.ScrollableHeight;
    }

    private static double Clamp(double value, double min, double max)
    {
        if (value < min)
        {
            return min;
        }

        return value > max ? max : value;
    }
}
