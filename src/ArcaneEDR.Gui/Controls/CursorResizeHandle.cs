using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Windows.Foundation;

namespace ArcaneEDR_Gui.Controls;

public sealed class CursorResizeHandle : Control
{
    public static readonly DependencyProperty CursorShapeProperty =
        DependencyProperty.Register(
            nameof(CursorShape),
            typeof(InputSystemCursorShape),
            typeof(CursorResizeHandle),
            new PropertyMetadata(InputSystemCursorShape.Arrow, OnCursorShapeChanged));

    private bool isDragging;
    private uint pointerId;
    private Point lastPosition;

    public event EventHandler<ResizeDeltaEventArgs>? ResizeDelta;

    public InputSystemCursorShape CursorShape
    {
        get => (InputSystemCursorShape)GetValue(CursorShapeProperty);
        set => SetValue(CursorShapeProperty, value);
    }

    public CursorResizeHandle()
    {
        IsTabStop = false;
        Loaded += (_, _) => ApplyCursor();
    }

    protected override void OnPointerPressed(PointerRoutedEventArgs e)
    {
        base.OnPointerPressed(e);
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
        {
            return;
        }

        isDragging = true;
        pointerId = e.Pointer.PointerId;
        lastPosition = GetStablePointerPosition(e);
        CapturePointer(e.Pointer);
        e.Handled = true;
    }

    protected override void OnPointerMoved(PointerRoutedEventArgs e)
    {
        base.OnPointerMoved(e);
        if (!isDragging || e.Pointer.PointerId != pointerId)
        {
            return;
        }

        Point position = GetStablePointerPosition(e);
        ResizeDelta?.Invoke(this, new ResizeDeltaEventArgs(position.X - lastPosition.X, position.Y - lastPosition.Y));
        lastPosition = position;
        e.Handled = true;
    }

    protected override void OnPointerReleased(PointerRoutedEventArgs e)
    {
        base.OnPointerReleased(e);
        CompleteDrag(e);
    }

    protected override void OnPointerCanceled(PointerRoutedEventArgs e)
    {
        base.OnPointerCanceled(e);
        CompleteDrag(e);
    }

    protected override void OnPointerCaptureLost(PointerRoutedEventArgs e)
    {
        base.OnPointerCaptureLost(e);
        isDragging = false;
    }

    private static void OnCursorShapeChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs e)
    {
        ((CursorResizeHandle)dependencyObject).ApplyCursor();
    }

    private void CompleteDrag(PointerRoutedEventArgs e)
    {
        if (!isDragging || e.Pointer.PointerId != pointerId)
        {
            return;
        }

        isDragging = false;
        ReleasePointerCapture(e.Pointer);
        e.Handled = true;
    }

    private void ApplyCursor()
    {
        ProtectedCursor = InputSystemCursor.Create(CursorShape);
    }

    private Point GetStablePointerPosition(PointerRoutedEventArgs e)
    {
        if (XamlRoot?.Content is UIElement root)
        {
            return e.GetCurrentPoint(root).Position;
        }

        return e.GetCurrentPoint(null).Position;
    }
}

public sealed class ResizeDeltaEventArgs : EventArgs
{
    public ResizeDeltaEventArgs(double horizontalChange, double verticalChange)
    {
        HorizontalChange = horizontalChange;
        VerticalChange = verticalChange;
    }

    public double HorizontalChange { get; }

    public double VerticalChange { get; }
}
