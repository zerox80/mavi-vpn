//! Linux application discovery and split-tunnel configuration.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Whether selected Linux applications use or bypass the VPN.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitTunnelMode {
    #[default]
    Disabled,
    /// Only the selected applications use the VPN.
    Include,
    /// Every application except the selected applications uses the VPN.
    Exclude,
}

/// An application selected from the Linux desktop application catalog.
///
/// The executable signature is discovered from the application's `.desktop`
/// entry. It is persisted internally so users never need to find or type an
/// executable path themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitTunnelApp {
    pub id: String,
    pub name: String,
    pub exec: Vec<String>,
}

/// Returns applications visible in the current Linux desktop environment.
/// User-local entries take precedence over system entries with the same ID.
#[must_use]
pub fn discover_linux_apps() -> Vec<SplitTunnelApp> {
    discover_linux_apps_in(&application_dirs())
}

fn application_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
        dirs.push(PathBuf::from(data_home).join("applications"));
    } else if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share/applications"));
    }

    let data_dirs =
        std::env::var_os("XDG_DATA_DIRS").unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    dirs.extend(std::env::split_paths(&data_dirs).map(|directory| directory.join("applications")));
    dirs
}

fn discover_linux_apps_in(dirs: &[PathBuf]) -> Vec<SplitTunnelApp> {
    let mut apps = Vec::new();
    let mut seen = HashSet::new();
    for directory in dirs {
        visit_desktop_entries(directory, directory, &mut seen, &mut apps);
    }
    apps.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });
    apps
}

fn visit_desktop_entries(
    root: &Path,
    directory: &Path,
    seen: &mut HashSet<String>,
    apps: &mut Vec<SplitTunnelApp>,
) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut entries = entries.flatten().collect::<Vec<_>>();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            visit_desktop_entries(root, &path, seen, apps);
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("desktop") {
            continue;
        }
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let id = relative
            .to_string_lossy()
            .replace(['/', '\\'], "-")
            .trim_end_matches(".desktop")
            .to_string();
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(app) = parse_desktop_entry(&id, &path) {
            apps.push(app);
        }
    }
}

fn parse_desktop_entry(id: &str, path: &Path) -> Option<SplitTunnelApp> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut in_desktop_entry = false;
    let mut name = None;
    let mut exec = None;
    let mut app_type = None;
    let mut hidden = false;
    let mut no_display = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_desktop_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_desktop_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Name" => name = Some(unescape_desktop_value(value)),
            "Exec" => exec = Some(value.to_string()),
            "Type" => app_type = Some(value),
            "Hidden" => hidden = value.eq_ignore_ascii_case("true"),
            "NoDisplay" => no_display = value.eq_ignore_ascii_case("true"),
            _ => {}
        }
    }

    if hidden || no_display || app_type != Some("Application") {
        return None;
    }
    let exec = executable_signature(exec?.as_str());
    if exec.is_empty() {
        return None;
    }
    Some(SplitTunnelApp {
        id: id.to_string(),
        name: name.filter(|value| !value.is_empty())?,
        exec,
    })
}

fn unescape_desktop_value(value: &str) -> String {
    value
        .replace("\\s", " ")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
        .replace("\\\\", "\\")
}

fn executable_signature(exec: &str) -> Vec<String> {
    let mut tokens = tokenize_exec(exec);
    while tokens.first().is_some_and(|token| token == "env") {
        tokens.remove(0);
        while tokens
            .first()
            .is_some_and(|token| token.contains('=') && !token.starts_with('='))
        {
            tokens.remove(0);
        }
    }
    let mut signature = Vec::new();
    for token in tokens {
        // Field codes are substituted with user-specific values by the
        // desktop launcher. Match the stable arguments before the first one
        // instead of persisting a value that can never equal the real argv.
        if contains_field_code(&token) {
            break;
        }
        signature.push(token.replace("%%", "%"));
    }
    signature
}

fn contains_field_code(token: &str) -> bool {
    let mut chars = token.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' && !matches!(chars.next(), Some('%')) {
            return true;
        }
    }
    false
}

fn tokenize_exec(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(active_quote) = quote {
            if ch == active_quote {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_visible_apps_with_user_precedence() {
        let temp = tempfile::tempdir().unwrap();
        let user = temp.path().join("user");
        let system = temp.path().join("system");
        std::fs::create_dir_all(&user).unwrap();
        std::fs::create_dir_all(system.join("nested")).unwrap();
        std::fs::write(
            user.join("browser.desktop"),
            "[Desktop Entry]\nType=Application\nName=My Browser\nExec=/opt/browser --new-window %U\n",
        )
        .unwrap();
        std::fs::write(
            system.join("browser.desktop"),
            "[Desktop Entry]\nType=Application\nName=Old Browser\nExec=/usr/bin/browser %U\n",
        )
        .unwrap();
        std::fs::write(
            system.join("nested/chat.desktop"),
            "[Desktop Entry]\nType=Application\nName=Chat App\nExec=flatpak run org.example.Chat\n",
        )
        .unwrap();

        let apps = discover_linux_apps_in(&[user, system]);

        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].name, "Chat App");
        assert_eq!(apps[0].id, "nested-chat");
        assert_eq!(apps[1].exec, ["/opt/browser", "--new-window"]);
    }

    #[test]
    fn ignores_hidden_non_application_and_invalid_entries() {
        let temp = tempfile::tempdir().unwrap();
        for (name, content) in [
            (
                "hidden.desktop",
                "[Desktop Entry]\nType=Application\nName=Hidden\nExec=hidden\nHidden=true\n",
            ),
            (
                "link.desktop",
                "[Desktop Entry]\nType=Link\nName=Link\nExec=link\n",
            ),
            (
                "missing.desktop",
                "[Desktop Entry]\nType=Application\nName=Missing\n",
            ),
        ] {
            std::fs::write(temp.path().join(name), content).unwrap();
        }
        assert!(discover_linux_apps_in(&[temp.path().to_path_buf()]).is_empty());
    }

    #[test]
    fn parses_quoted_exec_and_removes_desktop_field_codes() {
        assert_eq!(
            executable_signature(r#"env FOO=bar "/opt/My App/app" --open=%u %F"#),
            ["/opt/My App/app"]
        );
        assert_eq!(
            executable_signature("viewer %%file %F"),
            ["viewer", "%file"]
        );
    }
}
