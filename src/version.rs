use serde_json::json;

pub fn version_text() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

pub fn version_json() -> String {
    json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "git_commit": env!("ONMAP_GIT_COMMIT"),
        "git_describe": env!("ONMAP_GIT_DESCRIBE"),
        "git_dirty": git_dirty_json(),
        "build_profile": env!("ONMAP_BUILD_PROFILE"),
    })
    .to_string()
}

fn git_dirty_json() -> Option<bool> {
    match env!("ONMAP_GIT_DIRTY") {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn version_json_has_expected_shape() {
        let value: Value =
            serde_json::from_str(&version_json()).expect("version JSON should parse");
        let object = value.as_object().expect("version JSON should be an object");

        assert_eq!(object.len(), 6);
        assert!(object.contains_key("name"));
        assert!(object.contains_key("version"));
        assert!(object.contains_key("git_commit"));
        assert!(object.contains_key("git_describe"));
        assert!(object.contains_key("git_dirty"));
        assert!(object.contains_key("build_profile"));
    }
}
