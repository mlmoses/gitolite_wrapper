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
    public static bool DecodeBase64(this ReadOnlySpan<byte> base64, out ReadOnlySpan<byte> decodedBytes)
    {
        var bytes = new byte[base64.Length];
        var success = Base64.DecodeFromUtf8(base64, bytes, out _, out var written) == OperationStatus.Done;
        decodedBytes = success ? new ReadOnlySpan<byte>(bytes, 0, written) : ReadOnlySpan<byte>.Empty;
        return success;
    }

    public static string DecodeText(this ReadOnlySpan<byte> textBytes, Encoding? encoding = null) =>
        (encoding ?? Encoding.UTF8).GetString(textBytes);
}
