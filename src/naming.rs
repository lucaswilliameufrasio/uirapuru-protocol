//! Names the hub and the agent must agree on.
//!
//! The agent runs `docker compose -p <project>` so two projects that both have
//! a service called `web` never share a Compose project, and the hub, which
//! never talks to Docker, can still tell where each replica answers on the
//! shared network (`<project>-<service>-<n>`).

use sha2::{Digest, Sha256};

/// Docker network every exposed service and every gateway joins.
pub const SHARED_NETWORK: &str = "uirapuru";

const MAX_SLUG: usize = 40;

fn slug(part: &str) -> String {
    let mut out = String::new();
    let mut last_dash = true;
    for c in part.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_matches('-').to_owned()
}

/// Compose project of a service stack, from its directory
/// (`<root>/<owner>/<repo>/<service>`): only the last three components count,
/// so the hub and the agent need not agree on the root.
pub fn compose_project_name(compose_dir: &str) -> String {
    let mut parts: Vec<&str> = compose_dir
        .trim_end_matches('/')
        .rsplit('/')
        .take(3)
        .collect();
    parts.reverse();
    let identity = parts.join("/");
    let mut readable = slug(&parts.join("-"));
    readable.truncate(MAX_SLUG);
    let readable = readable.trim_end_matches('-');
    let digest = Sha256::digest(identity.as_bytes());
    let hash: String = digest.iter().take(3).map(|b| format!("{b:02x}")).collect();
    if readable.is_empty() {
        format!("uir-{hash}")
    } else {
        format!("uir-{readable}-{hash}")
    }
}

/// Name Docker's DNS resolves, on a shared network, for replica `index`
/// (1-based) of a Compose service.
pub fn replica_dns_name(project: &str, service: &str, index: u32) -> String {
    format!("{project}-{service}-{index}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_names_are_stable_unique_and_docker_safe() {
        let a = compose_project_name("/opt/uirapuru/services/acme/shop/web");
        assert_eq!(a, compose_project_name("/srv/other-root/acme/shop/web/"));
        assert_ne!(a, compose_project_name("/opt/x/acme/blog/web"));
        assert_ne!(a, compose_project_name("/opt/x/acme-shop/web"));
        assert!(a.starts_with("uir-acme-shop-web-"), "{a}");
        for name in [
            a,
            compose_project_name("/r/Ac Me/Shop_API/Web.v2"),
            compose_project_name(&format!("/r/{}/b/c", "x".repeat(200))),
            compose_project_name("////"),
        ] {
            assert!(name.len() <= 63, "{name}");
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{name}"
            );
            assert!(name.starts_with("uir-"));
        }
    }

    #[test]
    fn replicas_are_numbered_from_one() {
        assert_eq!(replica_dns_name("uir-a-1", "web", 2), "uir-a-1-web-2");
    }
}
