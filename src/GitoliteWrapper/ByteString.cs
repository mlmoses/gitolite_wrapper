using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace GitoliteWrapper;

internal sealed class ByteString : IReadOnlyList<byte>, IEquatable<ByteString>
{
    /// <summary>
    /// Gets the byte array containing the bytes for this <see cref="ByteString"/>.
    /// </summary>
    private byte[] Bytes { get; }

    /// <summary>
    /// Gets the offset into <see cref="Bytes"/> where this <see cref="ByteString"/>'s data begins.
    /// </summary>
    private int Offset { get; }

    /// <summary>
    /// Gets the number of bytes in this <see cref="ByteString"/>.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Returns true if the length of this <see cref="ByteString"/> is 0, false otherwise.
    /// </summary>
    public bool IsEmpty => Length == 0;

    int IReadOnlyCollection<byte>.Count => Length;

    #region Operators

    public static explicit operator ByteString(ReadOnlySpan<byte> bytes) =>
        bytes.IsEmpty ? Empty : new ByteString(bytes);

    public static explicit operator ByteString(ReadOnlyMemory<byte> bytes) =>
        bytes.IsEmpty ? Empty : new ByteString(bytes);

    public static implicit operator ReadOnlySpan<byte>(ByteString byteString) => byteString.AsReadOnlySpan();

    public static implicit operator ReadOnlyMemory<byte>(ByteString byteString) => byteString.AsReadOnlyMemory();

    public static bool operator ==(ByteString? lhs, ByteString? rhs) => lhs?.Equals(rhs) ?? ReferenceEquals(rhs, null);

    public static bool operator !=(ByteString? lhs, ByteString? rhs) =>
        !(lhs?.Equals(rhs) ?? ReferenceEquals(rhs, null));

    #endregion

    /// <summary>
    /// Reads the contents of the specified <see cref="Stream"/> into a new <see cref="ByteString"/>.
    /// </summary>
    /// <param name="stream">The stream from which to read.</param>
    /// <param name="trimThreshold">The maximum number of unused bytes that can remain in the internal buffer without
    /// creating a new buffer for the result.</param>
    /// <returns>A new <see cref="ByteString"/> containing the data read from the <paramref name="stream"/>.</returns>
    /// <remarks>
    /// <para>If the stream is seekable, this method will attempt to compute the amount of data to be read from the
    /// <see cref="Stream.Length"/> and <see cref="Stream.Position"/> properties. It will pre-allocate the memory needed
    /// and stop reading when it is full. If the amount of data needed cannot be computed, it will fall back to a
    /// default initial size, allocating new, larger buffers as necessary to contain the data being read. When the
    /// reading is complete, it will create a new, final buffer to hold the data if the number of unused bytes in the
    /// current buffer exceeds <paramref name="trimThreshold"/>.</para>
    /// </remarks>
    public static ByteString From(Stream stream, int trimThreshold = 0)
    {
        var resizable = true;
        var size = 1024L;
        if (stream.CanSeek)
        {
            try
            {
                size = stream.Length - stream.Position;
                if (size == 0)
                    return Empty;

                resizable = false;
            }
            catch (NotSupportedException)
            {
                // Nothing to do here!
            }
        }

        var buffer = new byte[size];

        var totalRead = 0;
        int read;
        do
        {
            if (resizable && totalRead == buffer.Length)
                buffer = buffer.Grow(2);

            read = stream.Read(buffer.AsSpan(totalRead, buffer.Length - totalRead));
            totalRead += read;
            if (!resizable && totalRead == buffer.Length)
                read = 0;
        } while (read > 0);

        ByteString result;
        if (totalRead == 0)
            result = Empty;
        else if (buffer.Length - totalRead > trimThreshold)
            result = new ByteString((ReadOnlySpan<byte>)buffer);
        else
            result = new ByteString(buffer, 0, totalRead);

        return result;
    }

    #region Constructors

    private ByteString(ReadOnlySpan<byte> bytes) : this(bytes.ToArray(), 0, bytes.Length)
    {
    }

    private ByteString(ReadOnlyMemory<byte> bytes) : this(bytes.ToArray(), 0, bytes.Length)
    {
    }

    private ByteString(byte[] bytes, int offset, int length)
    {
        if (offset < 0 || bytes.Length < offset)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (length < 0 || length > bytes.Length - offset)
            throw new ArgumentOutOfRangeException(nameof(length));

        Bytes = bytes;
        Offset = offset;
        Length = length;
    }

    #endregion

    /// <summary>
    /// The only instance of an empty <see cref="ByteString"/>.
    /// </summary>
    public static ByteString Empty { get; } = new(ReadOnlySpan<byte>.Empty);

    /// <summary>
    /// Gets the byte at the specified offset in this <see cref="ByteString"/>.
    /// </summary>
    /// <param name="offset">The offset of the byte to return.</param>
    /// <exception cref="ArgumentOutOfRangeException">If offset is outside the bounds of this
    /// <see cref="ByteString"/>.</exception>
    public byte this[int offset]
    {
        get
        {
            if (offset < 0 || Length <= offset)
                throw new ArgumentOutOfRangeException(nameof(offset));
            return Bytes[Offset + offset];
        }
    }

    /// <summary>
    /// Gets a new <see cref="ByteString"/> representing the specified from this <see cref="ByteString"/>.
    /// </summary>
    /// <param name="range">The <see cref="Range"/> of data to be returned.</param>
    /// <exception cref="ArgumentOutOfRangeException">If <paramref name="range"/> is outside the bounds of this
    /// <see cref="ByteString"/>.</exception>
    /// <remarks>
    /// <para>If the specified range resolves to all the data contained in this <see cref="ByteString"/>, then a
    /// reference to this <see cref="ByteString"/> is returned instead of creating a new instance.</para>
    /// </remarks>
    public ByteString this[Range range]
    {
        get
        {
            var (offset, length) = range.GetOffsetAndLength(Length);
            if (offset < 0 || Length <= offset)
                throw new ArgumentOutOfRangeException(nameof(range));
            if (length <= 0)
                return Empty;
            if (offset == 0 && length == Length)
                return this;
            return new ByteString(Bytes, Offset + offset, length);
        }
    }

    /// <summary>
    /// Returns a new <see cref="ReadOnlySpan{T}"/> for this <see cref="ByteString"/>.
    /// </summary>
    /// <returns>A new <see cref="ReadOnlySpan{T}"/> for this <see cref="ByteString"/>.</returns>
    /// <remarks>
    /// <para>It is usually more convenient to use the implicit cast operator, which just invokes this method.</para>
    /// </remarks>
    public ReadOnlySpan<byte> AsReadOnlySpan() => new(Bytes, Offset, Length);

    /// <summary>
    /// Returns a new <see cref="ReadOnlyMemory{T}"/> for this <see cref="ByteString"/>.
    /// </summary>
    /// <returns>A new <see cref="ReadOnlyMemory{T}"/> for this <see cref="ByteString"/>.</returns>
    /// <remarks>
    /// <para>It is usually more convenient to use the implicit cast operator, which just invokes this method.</para>
    /// </remarks>
    public ReadOnlyMemory<byte> AsReadOnlyMemory() => new(Bytes, Offset, Length);

    /// <summary>
    /// Returns a new <see cref="ByteString"/> that is a copy of this one with any extraneous data removed.
    /// </summary>
    /// <returns>A new <see cref="ByteString"/> containing the same data as this one.</returns>
    /// <remarks>
    /// <para>Since a <see cref="ByteString"/> created from another <see cref="ByteString"/> will share the same
    /// underlying memory, this method can be useful to avoid keeping extra data around in memory. This can be useful
    /// when parsing data in memory, and you want to retain a record that was parsed from the data without having to
    /// keep the entire dataset. This method does require a copy to accomplish its goal.</para>
    /// <para>If there is no extraneous data, this method simply returns a reference to the current object.</para>
    /// </remarks>
    public ByteString Compact() =>
        Offset > 0 || Length != Bytes.Length
            ? new ByteString(((ReadOnlySpan<byte>)Bytes).Slice(Offset, Length))
            : this;

    #region IEnumerable<byte> implementations

    IEnumerator<byte> IEnumerable<byte>.GetEnumerator() => new Enumerator(this);

    System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() =>
        ((IEnumerable<byte>)this).GetEnumerator();

    private sealed class Enumerator(ByteString bytes) : IEnumerator<byte>
    {
        private int _index = -1;

        void IDisposable.Dispose()
        {
        }

        public byte Current
        {
            get
            {
                if (_index < 0)
                    throw new InvalidOperationException("Call MoveNext() first.");
                return bytes[_index];
            }
        }

        object System.Collections.IEnumerator.Current => Current;

        public bool MoveNext() => _index < bytes.Length && ++_index < bytes.Length;

        public void Reset() => _index = -1;
    }

    #endregion

    #region Equality

    private int _hashCode;

    [SuppressMessage("ReSharper", "NonReadonlyMemberInGetHashCode")]
    public override int GetHashCode()
    {
        if (_hashCode != 0)
            return _hashCode;

        var count = Math.Min(256, Length);
        var result = 17;
        for (var i = 0; i < count; i++)
            result = 31 * result + Bytes[i].GetHashCode();

        _hashCode = result;
        return result;
    }

    public override bool Equals(object? obj) => obj is ByteString && Equals(obj);

    public bool Equals(ByteString? other)
    {
        if (other == null)
            return false;

        if (ReferenceEquals(this, other))
            return true;

        if (Length != other.Length)
            return false;

        if (ReferenceEquals(Bytes, other.Bytes))
            return Offset == other.Offset;

        for (var i = 0; i < Length; i++)
            if (this[i] != other[i])
                return false;

        return true;
    }

    #endregion
}