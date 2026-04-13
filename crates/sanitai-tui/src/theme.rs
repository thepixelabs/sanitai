use ratatui::style::Color;

pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub focus: Color,
    pub muted: Color,
    pub safe: Color,
    pub warn: Color,
    pub danger: Color,
}

/// Default: rich 256-color midnight navy palette.
pub const MIDNIGHT: Theme = Theme {
    bg: Color::Indexed(233),
    fg: Color::Indexed(230),
    focus: Color::Indexed(51),
    muted: Color::Indexed(241),
    safe: Color::Indexed(85),
    warn: Color::Indexed(222),
    danger: Color::Indexed(210),
};

/// Void: accessible 8-color theme for terminals that don't support 256 colors.
pub const VOID: Theme = Theme {
    bg: Color::Black,
    fg: Color::White,
    focus: Color::Cyan,
    muted: Color::DarkGray,
    safe: Color::Green,
    warn: Color::Yellow,
    danger: Color::Red,
};
