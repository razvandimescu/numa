fn main() {
    // --long forces "TAG-N-gSHA[-dirty]" format even on exact tag matches,
    // making parsing unambiguous for pre-release tags like v0.14.0-rc1.
    let git_version = std::process::Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty", "--long"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|raw| parse_git_describe(raw.trim()));

    if let Some(v) = git_version {
        println!("cargo:rustc-env=NUMA_BUILD_VERSION={}", v);
    }

    println!("cargo:rerun-if-changed=.git/HEAD");
}

/// Parse `git describe --long` output into a SemVer-compatible string.
///   "v0.13.1-0-ga87f907"          → "0.13.1"
///   "v0.13.1-9-ga87f907"          → "0.13.1+a87f907"
///   "v0.14.0-rc1-0-ga87f907"      → "0.14.0-rc1"
///   "v0.14.0-rc1-3-ga87f907-dirty" → "0.14.0-rc1+a87f907-dirty"
///   "a87f907"                      → "0.0.0+a87f907"
fn parse_git_describe(s: &str) -> Option<String> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let dirty = s.ends_with("-dirty");
    let s = s.strip_suffix("-dirty").unwrap_or(s);

    // --long format: TAG-N-gSHA. Split from the right so tags with hyphens work.
    let gpos = s.rfind("-g")?;
    let sha = &s[gpos + 2..];
    let rest = &s[..gpos];
    let npos = rest.rfind('-')?;
    let n: u32 = rest[npos + 1..].parse().ok()?;
    let tag = &rest[..npos];

    if tag.is_empty() {
        return Some(format!("0.0.0+{}", sha));
    }

    Some(match (n, dirty) {
        (0, false) => tag.to_string(),
        (0, true) => format!("{}+{}-dirty", tag, sha),
        (_, false) => format!("{}+{}", tag, sha),
        (_, true) => format!("{}+{}-dirty", tag, sha),
    })
}
