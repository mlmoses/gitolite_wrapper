using System;

namespace GitoliteWrapper;

internal sealed class UserAuthParser
{
    private const byte CharA = (byte)'a';
    private const byte CharAUp = (byte)'A';
    private const byte CharZ = (byte)'z';
    private const byte CharZUp = (byte)'Z';
    private const byte Char0 = (byte)'0';
    private const byte Char9 = (byte)'9';
    private const byte CharP = (byte)'p';
    private const byte CharU = (byte)'u';
    private const byte CharB = (byte)'b';
    private const byte CharL = (byte)'l';
    private const byte CharI = (byte)'i';
    private const byte CharC = (byte)'c';
    private const byte CharK = (byte)'k';
    private const byte CharE = (byte)'e';
    private const byte CharY = (byte)'y';
    private const byte CharSpace = (byte)' ';
    private const byte CharTab = (byte)'\t';
    private const byte CharNewLine = (byte)'\n';
    private const byte CharPlus = (byte)'+';
    private const byte CharSlash = (byte)'/';
    private const byte CharEquals = (byte)'=';

    private enum Status
    {
        Processing,
        Success,
        Error
    }

    private sealed class State(ByteString content)
    {
        private ByteString Content { get; } = content;

        public Status Status { get; set; } = Status.Processing;
        
        public Action<State> Action { get; set; } = StateBeginLine;

        private int? KeyTypeStart { get; set; }
        public void SetKeyTypeStart() => KeyTypeStart = Offset;

        private int? KeyTypeEnd { get; set; }
        public void SetKeyTypeEnd() => KeyTypeEnd = Offset;

        private int? KeyStart { get; set; }
        public void SetKeyStart() => KeyStart = Offset;

        private int? KeyEnd { get; set; }
        public void SetKeyEnd() => KeyEnd = Offset;

        private int _offset;

        public int Offset
        {
            get => _offset;
            set
            {
                _offset = value;
                Byte = Content[value];
            }
        }

        public byte Byte { get; private set; }

        public ByteString KeyType => GetSubContent(KeyTypeStart, KeyTypeEnd);

        public ByteString Key => GetSubContent(KeyStart, KeyEnd);

        private ByteString GetSubContent(int? maybeStart, int? maybeEnd)
        {
            if (Status != Status.Success || maybeStart == null)
                return ByteString.Empty;

            var start = (int)maybeStart;
            var end = maybeEnd ?? Offset;
            if (end < start)
                throw new InvalidOperationException();

            return Content[start..end];
        }

        public void ResetForNewLine()
        {
            KeyTypeStart = null;
            KeyTypeEnd = null;
            KeyStart = null;
            KeyEnd = null;
            Action = StateBeginLine;
        }

        public bool IsBase64Char => (CharAUp <= Byte && Byte <= CharZUp)
                                      || (CharA <= Byte && Byte <= CharZ)
                                      || (Char0 <= Byte && Byte <= Char9)
                                      || CharPlus == Byte
                                      || CharSlash == Byte
                                      || CharEquals == Byte;

        public bool IsWhiteSpace => CharSpace == Byte || CharTab == Byte;

        public bool IsNewLine => CharNewLine == Byte;
    }

    public static (ByteString, ByteString) FindPublicKey(ByteString userAuthContent)
    {
        var state = new State(userAuthContent);

        var l = userAuthContent.Length;
        for (var i = 0; i < l && state.Status == Status.Processing; i++)
        {
            state.Offset = i;
            state.Action(state);
        }

        return (state.KeyType, state.Key);
    }

    private static void StateBeginLine(State state) => ExpectChar(CharP, StateFoundP, state);

    private static void StateFoundP(State state) => ExpectChar(CharU, StateFoundU, state);

    private static void StateFoundU(State state) => ExpectChar(CharB, StateFoundB, state);

    private static void StateFoundB(State state) => ExpectChar(CharL, StateFoundL, state);

    private static void StateFoundL(State state) => ExpectChar(CharI, StateFoundI, state);

    private static void StateFoundI(State state) => ExpectChar(CharC, StateFoundC, state);

    private static void StateFoundC(State state) => ExpectChar(CharK, StateFoundK, state);

    private static void StateFoundK(State state) => ExpectChar(CharE, StateFoundE, state);

    private static void StateFoundE(State state) => ExpectChar(CharY, StateWhitespace1, state);

    private static void ExpectChar(byte expected, Action<State> nextAction, State state)
    {
        if (state.IsNewLine)
            state.Action = StateBeginLine;
        else if (state.Byte == expected)
            state.Action = nextAction;
        else
            state.Action = StateIgnoreToEndOfLine;
    }

    private static void StateWhitespace1(State state)
    {
        if (state.IsNewLine)
        {
            state.Action = StateBeginLine;
        }
        else if (!state.IsWhiteSpace)
        {
            state.SetKeyTypeStart();
            state.Action = StateKeyType;
        }
    }

    private static void StateKeyType(State state)
    {
        if (state.IsNewLine)
        {
            state.ResetForNewLine();
        }
        else if (state.IsWhiteSpace)
        {
            state.SetKeyTypeEnd();
            state.Action = StateWhitespace2;
        }
    }

    private static void StateWhitespace2(State state)
    {
        if (state.IsNewLine)
        {
            state.ResetForNewLine();
        }
        else if (state.IsBase64Char)
        {
            state.SetKeyStart();
            state.Action = StateKey;
        }
        else if (!state.IsWhiteSpace)
        {
            state.Action = StateIgnoreToEndOfLine;
        }
    }

    private static void StateKey(State state)
    {
        if (state.IsNewLine)
        {
            state.SetKeyEnd();
            state.Status = Status.Success;
        }
        else if (!state.IsBase64Char)
        {
            state.Action = StateIgnoreToEndOfLine;
        }
    }

    private static void StateIgnoreToEndOfLine(State state)
    {
        if (state.IsNewLine)
            state.ResetForNewLine();
    }
}