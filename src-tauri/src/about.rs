//! Keep the native macOS About panel in step with the cross-platform About pane.
use serde::Deserialize;
use tauri::menu::{AboutMetadata, Menu, PredefinedMenuItem};

#[derive(Deserialize)]
struct Product {
    tagline: String,
    repository: String,
    copyright: String,
    license: String,
}

pub(crate) fn menu(app: &tauri::AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let product: Product = serde_json::from_str(include_str!("../../src/brand/product.json"))
        .expect("embedded product metadata must be valid");
    let menu = Menu::default(app)?;
    // Tauri's default macOS application submenu begins with its About item.
    // Preserve the native Edit, Window, Help, Services and application actions.
    if let Some(application) = menu.items()?.first().and_then(|item| item.as_submenu()) {
        let about = PredefinedMenuItem::about(
            app,
            None,
            Some(AboutMetadata {
                name: Some(app.package_info().name.clone()),
                version: Some(app.package_info().version.to_string()),
                copyright: Some(product.copyright),
                credits: Some(format!(
                    "{}\n\n{}\n\n{}\nFormerly SSHelter.",
                    product.tagline, product.repository, product.license,
                )),
                icon: app.default_window_icon().cloned(),
                ..Default::default()
            }),
        )?;
        application.remove_at(0)?;
        application.prepend(&about)?;
    }
    Ok(menu)
}
