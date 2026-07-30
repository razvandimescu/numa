use std::io::IsTerminal;
use std::sync::LazyLock;

pub struct Palette {
    pub brand: &'static str,
    pub brand_bold: &'static str,
    pub olive: &'static str,
    pub dim: &'static str,
    pub dim_italic: &'static str,
    pub warning: &'static str,
    pub cyan: &'static str,
    pub green: &'static str,
    pub bold: &'static str,
    pub reset: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ColorLevel {
    None,
    Ansi256,
    Truecolor,
}

static PALETTE: LazyLock<Palette> = LazyLock::new(|| {
    let no_color = std::env::var_os("NO_COLOR");
    let colorterm = std::env::var("COLORTERM").ok();
    Palette::for_level(select_level(
        no_color_enabled(no_color.as_deref()),
        std::io::stderr().is_terminal(),
        colorterm.as_deref(),
    ))
});

pub fn get() -> &'static Palette {
    &PALETTE
}

fn no_color_enabled(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty())
}

fn select_level(no_color: bool, is_terminal: bool, colorterm: Option<&str>) -> ColorLevel {
    if no_color || !is_terminal {
        ColorLevel::None
    } else if colorterm.is_some_and(|value| {
        value.eq_ignore_ascii_case("truecolor") || value.eq_ignore_ascii_case("24bit")
    }) {
        ColorLevel::Truecolor
    } else {
        ColorLevel::Ansi256
    }
}

impl Palette {
    fn for_level(level: ColorLevel) -> Self {
        match level {
            ColorLevel::None => Self {
                brand: "",
                brand_bold: "",
                olive: "",
                dim: "",
                dim_italic: "",
                warning: "",
                cyan: "",
                green: "",
                bold: "",
                reset: "",
            },
            ColorLevel::Ansi256 => Self {
                brand: "\x1b[38;5;131m",
                brand_bold: "\x1b[1;38;5;131m",
                olive: "\x1b[38;5;65m",
                dim: "\x1b[38;5;246m",
                dim_italic: "\x1b[3;38;5;246m",
                warning: "\x1b[38;5;179m",
                cyan: "\x1b[38;5;44m",
                green: "\x1b[38;5;40m",
                bold: "\x1b[1m",
                reset: "\x1b[0m",
            },
            ColorLevel::Truecolor => Self {
                brand: "\x1b[38;2;192;98;58m",
                brand_bold: "\x1b[1;38;2;192;98;58m",
                olive: "\x1b[38;2;107;124;78m",
                dim: "\x1b[38;2;163;152;136m",
                dim_italic: "\x1b[3;38;2;163;152;136m",
                warning: "\x1b[38;2;204;176;59m",
                cyan: "\x1b[36m",
                green: "\x1b[32m",
                bold: "\x1b[1m",
                reset: "\x1b[0m",
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_requires_a_non_empty_value() {
        assert!(!no_color_enabled(None));
        assert!(!no_color_enabled(Some(std::ffi::OsStr::new(""))));
        assert!(no_color_enabled(Some(std::ffi::OsStr::new("1"))));
    }

    #[test]
    fn color_level_respects_output_and_environment() {
        assert_eq!(
            select_level(true, true, Some("truecolor")),
            ColorLevel::None
        );
        assert_eq!(
            select_level(false, false, Some("truecolor")),
            ColorLevel::None
        );
        assert_eq!(select_level(false, true, None), ColorLevel::Ansi256);
        assert_eq!(
            select_level(false, true, Some("24bit")),
            ColorLevel::Truecolor
        );
        assert_eq!(
            select_level(false, true, Some("TRUECOLOR")),
            ColorLevel::Truecolor
        );
    }

    #[test]
    fn disabled_palette_has_no_escape_codes() {
        let palette = Palette::for_level(ColorLevel::None);
        assert!(palette.brand.is_empty());
        assert!(palette.bold.is_empty());
        assert!(palette.reset.is_empty());
    }
}
