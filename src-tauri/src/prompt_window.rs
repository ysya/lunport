//! Position independent approval windows without tying their lifetime to the main
//! window: CLI/agent requests must still work while the workspace is hidden.
use tauri::{Manager, PhysicalPosition, PhysicalSize, WebviewWindow};

#[derive(Clone, Copy)]
struct Rect {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

impl Rect {
    fn from_physical(position: PhysicalPosition<i32>, size: PhysicalSize<u32>, scale: f64) -> Self {
        Self {
            x: f64::from(position.x) / scale,
            y: f64::from(position.y) / scale,
            width: f64::from(size.width) / scale,
            height: f64::from(size.height) / scale,
        }
    }
}

fn centered_position(anchor: Option<Rect>, work: Rect, size: (f64, f64)) -> (f64, f64) {
    let anchor = anchor.unwrap_or(work);
    let axis = |origin: f64, extent: f64, start: f64, available: f64, length: f64| {
        (origin + (extent - length) / 2.0).clamp(start, start + (available - length).max(0.0))
    };
    (
        axis(anchor.x, anchor.width, work.x, work.width, size.0),
        axis(anchor.y, anchor.height, work.y, work.height, size.1),
    )
}

/// macOS scales global window/monitor coordinates with each object's own backing
/// scale. Convert them to AppKit points before moving between Retina/non-Retina
/// screens. Windows/Linux use a shared physical desktop coordinate space.
fn coordinate_scale(backing_scale: f64) -> f64 {
    if cfg!(target_os = "macos") {
        backing_scale
    } else {
        1.0
    }
}

fn place(window: &WebviewWindow) -> tauri::Result<()> {
    let main = window.app_handle().get_webview_window("main");
    let monitor = main
        .as_ref()
        .and_then(|main| main.current_monitor().ok().flatten())
        .or_else(|| window.primary_monitor().ok().flatten())
        .or_else(|| window.current_monitor().ok().flatten());
    let Some(monitor) = monitor else {
        return window.center();
    };
    let work = monitor.work_area();
    let work = Rect::from_physical(
        work.position,
        work.size,
        coordinate_scale(monitor.scale_factor()),
    );
    let anchor = main.as_ref().and_then(|main| {
        // Minimized Windows windows can report the sentinel position -32000.
        // Hidden workspace windows still retain a useful position.
        if main.is_minimized().unwrap_or(false) {
            return None;
        }
        Some(Rect::from_physical(
            main.outer_position().ok()?,
            main.outer_size().ok()?,
            coordinate_scale(main.scale_factor().ok()?),
        ))
    });
    let size = window
        .outer_size()?
        .to_logical::<f64>(window.scale_factor()?);
    // The destination display determines the physical size after a DPI change.
    let scale = monitor.scale_factor() / coordinate_scale(monitor.scale_factor());
    let (x, y) = centered_position(anchor, work, (size.width * scale, size.height * scale));
    #[cfg(target_os = "macos")]
    return window.set_position(tauri::LogicalPosition::new(x, y));
    #[cfg(not(target_os = "macos"))]
    window.set_position(PhysicalPosition::new(x.round() as i32, y.round() as i32))
}

/// Called only for a newly shown question, never on background queue updates:
/// don't move the prompt or steal focus while the person is typing an answer.
pub(crate) fn show(window: &WebviewWindow) {
    if let Err(error) = place(window) {
        eprintln!(
            "[window] cannot position {} prompt: {error}",
            window.label()
        );
    }
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN: Rect = Rect {
        x: 200.0,
        y: 100.0,
        width: 1100.0,
        height: 720.0,
    };
    const WORK: Rect = Rect {
        x: 0.0,
        y: 25.0,
        width: 1920.0,
        height: 1015.0,
    };

    #[test]
    fn prompt_is_centered_over_workspace_including_its_frame() {
        assert_eq!(
            centered_position(Some(MAIN), WORK, (480.0, 348.0)),
            (510.0, 286.0)
        );
    }

    #[test]
    fn left_and_upper_monitors_keep_their_negative_coordinates() {
        let work = Rect {
            x: -1920.0,
            y: -1080.0,
            ..WORK
        };
        let main = Rect {
            x: -1800.0,
            y: -1000.0,
            ..MAIN
        };
        assert_eq!(
            centered_position(Some(main), work, (480.0, 348.0)),
            (-1490.0, -814.0)
        );
    }

    #[test]
    fn prompt_follows_workspace_to_another_monitor() {
        let main = Rect {
            x: MAIN.x + 1920.0,
            ..MAIN
        };
        let work = Rect { x: 1920.0, ..WORK };
        assert_eq!(
            centered_position(Some(main), work, (480.0, 348.0)),
            (2430.0, 286.0)
        );
    }

    #[test]
    fn partial_offscreen_workspace_does_not_hide_prompt_behind_dock_or_menu() {
        let corner = Rect {
            x: 1800.0,
            y: 900.0,
            ..MAIN
        };
        assert_eq!(
            centered_position(Some(corner), WORK, (480.0, 348.0)),
            (1440.0, 692.0)
        );
        let corner = Rect {
            x: -1000.0,
            y: -700.0,
            ..MAIN
        };
        assert_eq!(
            centered_position(Some(corner), WORK, (480.0, 348.0)),
            (0.0, 25.0)
        );
    }

    #[test]
    fn hidden_host_without_workspace_geometry_uses_monitor_work_area() {
        assert_eq!(
            centered_position(None, WORK, (480.0, 348.0)),
            (720.0, 358.5)
        );
    }

    #[test]
    fn small_display_keeps_oversized_prompt_titlebar_accessible() {
        let work = Rect {
            x: -800.0,
            y: 25.0,
            width: 400.0,
            height: 300.0,
        };
        assert_eq!(
            centered_position(None, work, (480.0, 348.0)),
            (-800.0, 25.0)
        );
    }

    #[test]
    fn macos_mixed_dpi_coordinates_are_compared_in_points() {
        // Main/target display is Retina; the hidden prompt was built on a 1x
        // display. Its global physical position cannot be copied directly.
        let main = Rect::from_physical(
            PhysicalPosition::new(-3600, 200),
            PhysicalSize::new(2200, 1440),
            2.0,
        );
        let work = Rect::from_physical(
            PhysicalPosition::new(-3840, 50),
            PhysicalSize::new(3840, 2030),
            2.0,
        );
        let prompt = PhysicalSize::new(480, 348).to_logical::<f64>(1.0);
        assert_eq!(
            centered_position(Some(main), work, (prompt.width, prompt.height)),
            (-1490.0, 286.0)
        );
        // The opposite move (Retina prompt to 1x target) preserves logical size.
        let prompt = PhysicalSize::new(960, 696).to_logical::<f64>(2.0);
        assert_eq!(
            centered_position(Some(MAIN), WORK, (prompt.width, prompt.height)),
            (510.0, 286.0)
        );
    }

    #[test]
    fn windows_dpi_change_uses_destination_pixel_size() {
        let main = Rect {
            x: 2200.0,
            y: 100.0,
            width: 1650.0,
            height: 1080.0,
        };
        let work = Rect {
            x: 1920.0,
            y: 0.0,
            width: 2560.0,
            height: 1400.0,
        };
        let prompt = PhysicalSize::new(480, 348).to_logical::<f64>(1.0);
        assert_eq!(
            centered_position(Some(main), work, (prompt.width * 1.5, prompt.height * 1.5)),
            (2665.0, 379.0)
        );
    }
}
