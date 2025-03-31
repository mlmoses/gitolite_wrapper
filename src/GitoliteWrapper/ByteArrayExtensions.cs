using System;

namespace GitoliteWrapper;

internal static class ByteArrayExtensions
{
    public static byte[] Grow(this byte[] buffer, int factor)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(factor);
        var newBuffer = new byte[buffer.Length / factor + buffer.Length];
        buffer.CopyTo(newBuffer.AsSpan());
        return newBuffer;
    }
}