use ::std::ops::Range;

pub struct AuthResult {
    pub key_type: Range<usize>,
    pub key: Range<usize>,
}

pub fn parse_user_auth(content: &[u8]) -> Option<AuthResult> {
    let mut state = State {
        status: Status::Parsing,
        offset: 0,
        byte: 0,
        key_type_start: None,
        key_type_end: None,
        key_start: None,
        key_end: None,
        action: action_begin_line,
    };
    let length = content.len();
    while state.offset < length {
        state.byte = content[state.offset];
        (state.action)(&mut state);
        state.offset += 1
    }

    match state.status {
        Status::Parsing => None,
        Status::Success => {
            if let (Some(key_type), Some(key)) = (state.key_type(), state.key()) {
                Some(AuthResult { key_type, key })
            } else {
                None
            }
        }
        Status::Error => None,
    }
}

pub enum Status {
    Parsing,
    Success,
    Error,
}

struct State {
    status: Status,
    offset: usize,
    byte: u8,
    key_type_start: Option<usize>,
    key_type_end: Option<usize>,
    key_start: Option<usize>,
    key_end: Option<usize>,
    action: fn(&mut State),
}

impl State {
    pub fn is_base64_value(&self) -> bool {
        let b = self.byte;
        b.is_ascii_uppercase()
            || b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || b'+' == b
            || b'/' == b
            || b'=' == b
    }

    pub fn is_new_line(&self) -> bool {
        self.byte == b'\n'
    }

    pub fn is_white_space(&self) -> bool {
        self.byte == b' ' || self.byte == b'\t'
    }

    pub fn key_type(&self) -> Option<Range<usize>> {
        to_range(self.key_type_start, self.key_type_end)
    }

    pub fn key(&self) -> Option<Range<usize>> {
        to_range(self.key_start, self.key_end)
    }

    pub fn reset_for_new_line(&mut self) {
        self.key_type_start = None;
        self.key_type_end = None;
        self.key_start = None;
        self.key_end = None;
    }
}

fn to_range(start: Option<usize>, end: Option<usize>) -> Option<Range<usize>> {
    if let (Some(start), Some(end)) = (start, end) {
        Some(start..end)
    } else {
        None
    }
}

fn expect_value(value: u8, next: fn(&mut State), state: &mut State) {
    state.action = if state.is_new_line() {
        action_begin_line
    } else if state.byte == value {
        next
    } else {
        action_ignore_to_eol
    };
}

fn action_begin_line(state: &mut State) {
    expect_value(b'p', action_found_p, state);
}

fn action_found_p(state: &mut State) {
    expect_value(b'u', action_found_u, state);
}

fn action_found_u(state: &mut State) {
    expect_value(b'b', action_found_b, state);
}

fn action_found_b(state: &mut State) {
    expect_value(b'l', action_found_l, state);
}

fn action_found_l(state: &mut State) {
    expect_value(b'i', action_found_i, state);
}

fn action_found_i(state: &mut State) {
    expect_value(b'c', action_found_c, state);
}

fn action_found_c(state: &mut State) {
    expect_value(b'k', action_found_k, state);
}

fn action_found_k(state: &mut State) {
    expect_value(b'e', action_found_e, state);
}

fn action_found_e(state: &mut State) {
    expect_value(b'y', action_found_y, state);
}

fn action_found_y(state: &mut State) {
    if state.is_new_line() {
        state.action = action_begin_line;
    } else if !state.is_white_space() {
        state.key_type_start = Some(state.offset);
        state.action = action_key_type;
    }
}

fn action_key_type(state: &mut State) {
    if state.is_new_line() {
        state.reset_for_new_line();
    } else if state.is_white_space() {
        state.key_type_end = Some(state.offset);
        state.action = action_found_key_type;
    }
}

fn action_found_key_type(state: &mut State) {
    if state.is_new_line() {
        state.reset_for_new_line();
    } else if state.is_base64_value() {
        state.key_start = Some(state.offset);
        state.action = action_key;
    } else if !state.is_white_space() {
        state.action = action_ignore_to_eol;
    }
}

fn action_key(state: &mut State) {
    if state.is_new_line() {
        state.key_end = Some(state.offset);
        state.status = Status::Success;
    } else if !state.is_base64_value() {
        state.action = action_ignore_to_eol;
    }
}

fn action_ignore_to_eol(state: &mut State) {
    if state.is_new_line() {
        state.reset_for_new_line();
    }
}
