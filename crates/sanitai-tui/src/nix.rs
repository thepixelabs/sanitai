use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Style},
    widgets::Widget,
};

use crate::menu::{COLOR_BG, COLOR_FG, COLOR_FOCUS, COLOR_WARN};

// ── Raccoon sprite palette ──────────────────────────────────────────────────
// Three-step warm fur: ivory highlight → amber midtone → burnt-orange shadow.
// Combined with a near-black bandit mask, they give the JRPG zone-shading
// depth effect without needing per-cell half-block styling.
const FUR_HI: Color = Color::Indexed(223); // ivory — snout / chest highlight
const FUR_MID: Color = Color::Indexed(179); // amber tan — main body fur
const FUR_SH: Color = Color::Indexed(130); // burnt orange — ears / shaded zones
const MASK: Color = Color::Indexed(235); // near-black — bandit eye mask
const DIM: Color = Color::Indexed(238); // medium gray — sleeping state

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NixMood {
    Normal,
    Alert,    // findings found
    Happy,    // clean scan
    Angry,    // critical threat / error state
    Sleeping, // idle / no activity
    WithSign, // warning with held sign
}

/// Returns 11 rows of `(text, fg_color)` for the current mood.
///
/// Sprite anatomy (≤18 display-width codepoints per row, single-width chars only):
///
///   rows  0–1  ear tips + head crown
///   rows  2–3  bandit mask band + eyes
///   rows  4–5  snout (light fill) + mouth
///   rows  6–8  torso
///   rows  9–10 legs + feet
///
/// Tail rings (░ ▒ alternating) hang off the right edge at rows 1–5.
/// Per-row colors create the zone-shading depth: MASK (near-black) for the
/// raccoon's face mask, FUR_HI (ivory) for the snout, FUR_SH (dark) for ears
/// and feet — no per-cell styling required.
fn body_rows(mood: NixMood) -> [(&'static str, Color); 11] {
    match mood {
        // ── Normal ──────────────────────────────────────────────────────────
        // Calm. Soft ◉ filled-circle eyes. ╰─────╯ gentle smile.
        // Arms relaxed (▗ ▖ stubs at sides). Tail rings on right: ░ ▒.
        NixMood::Normal => [
            (" \u{2597}\u{2584}\u{2596}         \u{2597}\u{2584}\u{2596} ", FUR_SH),  //  ▗▄▖         ▗▄▖
            (" \u{2590}\u{2588}\u{2588}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2588}\u{2588}\u{258c}\u{2591}  ", FUR_MID), // ▐██▄▄▄▄▄▄▄██▌░
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2588}\u{258c}\u{2592}   ", MASK),    // ▐█▓▓▓▓▓▓▓▓█▌▒
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{25c9}\u{2593}\u{2593}\u{2593}\u{25c9}\u{2593}\u{2588}\u{258c}\u{2591}   ", MASK),    // ▐█▓▓◉▓▓▓◉▓█▌░
            (" \u{2590}\u{2588}\u{2588}\u{2593}\u{2592}\u{2592}\u{2592}\u{2592}\u{2593}\u{2588}\u{2588}\u{258c}\u{2592}   ", FUR_HI),  // ▐██▓▒▒▒▒▓██▌▒
            (" \u{2590}\u{2588}\u{2588}\u{2588}\u{2570}\u{2500}\u{2500}\u{2500}\u{256f}\u{2588}\u{2588}\u{258c}\u{2591}   ", FUR_HI),  // ▐███╰───╯██▌░
            (" \u{2597}\u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}\u{2596}    ", FUR_MID), // ▗▐████████▌▖
            ("  \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", FUR_MID), //  ▐████████▌
            ("  \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", FUR_SH),  //  ▐████████▌ (shaded)
            ("   \u{2590}\u{2588}\u{2588}\u{2588}\u{258c} \u{2590}\u{2588}\u{2588}\u{2588}\u{258c}   ", FUR_SH),  //   ▐███▌ ▐███▌
            ("   \u{2580}\u{2588}\u{2588}\u{2588}\u{2580} \u{2580}\u{2588}\u{2588}\u{2588}\u{2580}   ", FUR_SH),  //   ▀███▀ ▀███▀
        ],

        // ── Alert ───────────────────────────────────────────────────────────
        // Wide ◈ lozenge eyes (pupils contracted). ! ! floaters between ears.
        // Open ╭───╮ worried mouth. Tail visible — tense but not angry.
        NixMood::Alert => [
            (" \u{2597}\u{2584}\u{2596}  ! !  \u{2597}\u{2584}\u{2596}  ", FUR_SH),  //  ▗▄▖  ! !  ▗▄▖
            (" \u{2590}\u{2588}\u{2588}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2588}\u{2588}\u{258c}\u{2591}  ", FUR_MID),
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2588}\u{258c}\u{2592}   ", MASK),
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{25c8}\u{2593}\u{2593}\u{2593}\u{25c8}\u{2593}\u{2588}\u{258c}\u{2591}   ", MASK),    // ◈ eyes
            (" \u{2590}\u{2588}\u{2588}\u{2593}\u{2592}\u{2592}\u{2592}\u{2592}\u{2593}\u{2588}\u{2588}\u{258c}\u{2592}   ", FUR_HI),
            (" \u{2590}\u{2588}\u{2588}\u{2588} \u{256d}\u{2500}\u{2500}\u{2500}\u{256e} \u{2588}\u{258c}\u{2591}  ", FUR_HI),  // ╭───╮ mouth
            (" \u{2597}\u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}\u{2596}    ", FUR_MID),
            ("  \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", FUR_MID),
            ("  \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", FUR_SH),
            ("   \u{2590}\u{2588}\u{2588}\u{2588}\u{258c} \u{2590}\u{2588}\u{2588}\u{2588}\u{258c}   ", FUR_SH),
            ("   \u{2580}\u{2588}\u{2588}\u{2588}\u{2580} \u{2580}\u{2588}\u{2588}\u{2588}\u{2580}   ", FUR_SH),
        ],

        // ── Happy ───────────────────────────────────────────────────────────
        // ★ star eyes. ★  ★ sparkles between ears. Wide ╰═════╯ grin.
        // Arms raised (▟▛ / ▜▙) — the victory pose.
        NixMood::Happy => [
            (" \u{2597}\u{2584}\u{2596} \u{2605}   \u{2605} \u{2597}\u{2584}\u{2596}  ", FUR_SH),  //  ▗▄▖ ★   ★ ▗▄▖
            (" \u{2590}\u{2588}\u{2588}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2588}\u{2588}\u{258c}\u{2591}  ", FUR_MID),
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2588}\u{258c}\u{2592}   ", MASK),
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{2605}\u{2593}\u{2593}\u{2593}\u{2605}\u{2593}\u{2588}\u{258c}\u{2591}   ", MASK),    // ★ eyes
            (" \u{2590}\u{2588}\u{2588}\u{2593}\u{2592}\u{2592}\u{2592}\u{2592}\u{2593}\u{2588}\u{2588}\u{258c}\u{2592}   ", FUR_HI),
            (" \u{2590}\u{2588}\u{2588}\u{2588}\u{2570}\u{2550}\u{2550}\u{2550}\u{256f}\u{2588}\u{2588}\u{258c}\u{2591}   ", FUR_HI),  // ╰═══╯ grin
            ("\u{259f}\u{259b}\u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}\u{259c}\u{259f}  ", FUR_MID), // ▟▛…▜▙ raised arms
            ("  \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", FUR_MID),
            ("  \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", FUR_SH),
            ("   \u{2590}\u{2588}\u{2588}\u{2588}\u{258c} \u{2590}\u{2588}\u{2588}\u{2588}\u{258c}   ", FUR_SH),
            ("   \u{2580}\u{2588}\u{2588}\u{2588}\u{2580} \u{2580}\u{2588}\u{2588}\u{2588}\u{2580}   ", FUR_SH),
        ],

        // ── Angry ───────────────────────────────────────────────────────────
        // ◈ eyes under ▀▀ furrowed-brow overhang. !!!! anger bursts above ears.
        // ╭═════╮ scowl. Arms up as fists (▛▙ / ▟▜).
        NixMood::Angry => [
            (" \u{2597}\u{2584}\u{2596} !!!! \u{2597}\u{2584}\u{2596}   ", FUR_SH),  //  ▗▄▖ !!!! ▗▄▖
            (" \u{2590}\u{2588}\u{2588}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2588}\u{2588}\u{258c}\u{2591}  ", FUR_MID),
            (" \u{2590}\u{2588}\u{2593}\u{2580}\u{2593}\u{2593}\u{2593}\u{2593}\u{2580}\u{2593}\u{2588}\u{258c}\u{2592}   ", MASK),    // ▀ furrowed brow
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{25c8}\u{2593}\u{2593}\u{2593}\u{25c8}\u{2593}\u{2588}\u{258c}\u{2591}   ", MASK),    // ◈ eyes
            (" \u{2590}\u{2588}\u{2588}\u{2593}\u{2592}\u{2592}\u{2592}\u{2592}\u{2593}\u{2588}\u{2588}\u{258c}\u{2592}   ", FUR_HI),
            (" \u{2590}\u{2588}\u{2588}\u{2588}\u{256d}\u{2550}\u{2550}\u{2550}\u{256e}\u{2588}\u{2588}\u{258c}\u{2591}   ", FUR_HI),  // ╭═══╮ scowl
            ("\u{259b}\u{259f}\u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}\u{259c}\u{259b}  ", FUR_MID), // ▛▙…▟▜ fists
            ("  \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", FUR_MID),
            ("  \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", FUR_SH),
            ("   \u{2590}\u{2588}\u{2588}\u{2588}\u{258c} \u{2590}\u{2588}\u{2588}\u{2588}\u{258c}   ", FUR_SH),
            ("   \u{2580}\u{2588}\u{2588}\u{2588}\u{2580} \u{2580}\u{2588}\u{2588}\u{2588}\u{2580}   ", FUR_SH),
        ],

        // ── Sleeping ────────────────────────────────────────────────────────
        // ── dashes for closed eyes. ─── flat mouth. z  Z floaters. No tail.
        // Whole sprite in DIM gray — curled, slouched, restful.
        NixMood::Sleeping => [
            (" \u{2597}\u{2584}\u{2596}  z   Z  \u{2597}\u{2584}\u{2596}  ", DIM),  //  ▗▄▖  z   Z  ▗▄▖
            (" \u{2590}\u{2588}\u{2588}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2588}\u{2588}\u{258c}    ", DIM),
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2588}\u{258c}     ", DIM),
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{2500}\u{2500}\u{2593}\u{2500}\u{2500}\u{2593}\u{2588}\u{258c}     ", DIM),  // ── ── closed eyes
            (" \u{2590}\u{2588}\u{2588}\u{2593}\u{2591}\u{2591}\u{2591}\u{2591}\u{2593}\u{2588}\u{2588}\u{258c}     ", DIM),  // dim ░ snout
            (" \u{2590}\u{2588}\u{2588}\u{2588} \u{2500}\u{2500}\u{2500} \u{2588}\u{2588}\u{258c}     ", DIM),  // ─── flat mouth
            ("  \u{2597}\u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}\u{2596}    ", DIM),  // narrowed torso
            ("   \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", DIM),
            ("   \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", DIM),
            ("   \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", DIM),  // legs together
            ("   \u{2580}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2580}     ", DIM),  // feet curled
        ],

        // ── WithSign ────────────────────────────────────────────────────────
        // Alert ◈ eyes. Right arm extended, holding a ⚠ placard (rows 5–7).
        // Sign panel floats to the right of the body.
        NixMood::WithSign => [
            (" \u{2597}\u{2584}\u{2596}  ! !  \u{2597}\u{2584}\u{2596}  ", FUR_SH),
            (" \u{2590}\u{2588}\u{2588}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}\u{2588}\u{2588}\u{258c}\u{2591}  ", FUR_MID),
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2588}\u{258c}\u{2592}   ", MASK),
            (" \u{2590}\u{2588}\u{2593}\u{2593}\u{25c8}\u{2593}\u{2593}\u{2593}\u{25c8}\u{2593}\u{2588}\u{258c}\u{2591}   ", MASK),
            (" \u{2590}\u{2588}\u{2588}\u{2593}\u{2592}\u{2592}\u{2592}\u{2592}\u{2593}\u{2588}\u{2588}\u{258c}\u{2592}   ", FUR_HI),
            (" \u{2590}\u{2588}\u{2588}\u{2588}\u{2570}\u{2500}\u{2500}\u{2500}\u{256f}\u{258c}\u{2584}\u{2584}\u{2584}\u{2584}\u{2584}", FUR_HI),  // arm → sign top ▄▄▄▄▄
            (" \u{2597}\u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}\u{258c}\u{26a0} !!!", COLOR_WARN),  // ▗▐██████▌▌⚠ !!!
            ("  \u{2590}\u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}\u{258c}\u{2580}\u{2580}\u{2580}\u{2580}\u{2580}", FUR_MID), // sign base ▀▀▀▀▀
            ("  \u{2590}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}\u{258c}     ", FUR_SH),
            ("   \u{2590}\u{2588}\u{2588}\u{2588}\u{258c} \u{2590}\u{2588}\u{2588}\u{2588}\u{258c}   ", FUR_SH),
            ("   \u{2580}\u{2588}\u{2588}\u{2588}\u{2580} \u{2580}\u{2588}\u{2588}\u{2588}\u{2580}   ", FUR_SH),
        ],
    }
}

/// Speech bubble + pixel-art body widget for the sidebar.
pub struct NixWidget {
    pub mood: NixMood,
    pub speech: Option<String>,
}

impl Widget for &NixWidget {
    fn render(self, area: Rect, buf: &mut Buffer) {
        // Flood the area with the background color so no stale cells show through.
        buf.set_style(area, Style::default().bg(COLOR_BG));

        let rows = body_rows(self.mood);

        // Speech bubble occupies the top 3 rows when present.
        let bubble_height: u16 = if self.speech.is_some() { 3 } else { 0 };
        let body_top = area.top().saturating_add(bubble_height);

        if let Some(ref text) = self.speech {
            let max_text = (area.width as usize).saturating_sub(4).min(text.len());
            let display = &text[..max_text];
            let bx = area.left();

            // Top border ╭──────╮
            let top = format!("\u{256d}{}\u{256e}", "\u{2500}".repeat(display.len() + 2));
            buf.set_string(bx, area.top(), &top, Style::default().fg(COLOR_FOCUS));

            // Text line │ text │
            let mid = format!("\u{2502} {} \u{2502}", display);
            buf.set_string(
                bx,
                area.top().saturating_add(1),
                &mid,
                Style::default().fg(COLOR_FG).bg(COLOR_BG),
            );

            // Bottom border ╰──────╯
            let bot = format!("\u{2570}{}\u{256f}", "\u{2500}".repeat(display.len() + 2));
            buf.set_string(
                bx,
                area.top().saturating_add(2),
                &bot,
                Style::default().fg(COLOR_FOCUS),
            );
        }

        // Render the body row by row, each with its own zone color.
        for (i, (line, color)) in rows.iter().enumerate() {
            let y = body_top.saturating_add(i as u16);
            if y >= area.bottom() {
                break;
            }
            buf.set_string(
                area.left(),
                y,
                line,
                Style::default().fg(*color).bg(COLOR_BG),
            );
        }
    }
}
