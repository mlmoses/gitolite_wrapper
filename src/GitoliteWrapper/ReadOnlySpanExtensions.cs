using System;
using System.Buffers;
using System.Buffers.Text;
using System.Text;

namespace GitoliteWrapper;

/// <summary>
/// Generic extension methods for spans of bytes.
/// </summary>
internal static class ReadOnlySpanExtensions
{
    public static bool DecodeBase64(this Span<byte> base64, out ReadOnlySpan<byte> data)
    {
        var success = Base64.DecodeFromUtf8InPlace(base64, out var written) == OperationStatus.Done && written > 0;
        data = success ? base64[..written] : ReadOnlySpan<byte>.Empty;
        return success;
    }

    public static string DecodeText(this ReadOnlySpan<byte> textBytes, Encoding? encoding = null) =>
        (encoding ?? Encoding.UTF8).GetString(textBytes);
}
