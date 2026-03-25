/// Represents a single pip package with its installed version.
#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub version: String,
}

/// Parses the output of `pip list` in both legacy and column formats:
///
/// Legacy:
///   Package    Version
///   ---------- -------
///   numpy      1.26.4
///
/// Also handles `pip list --format=freeze` (name==version) as a bonus.
pub fn parse_pip_list(input: &str) -> Vec<Package> {
    let mut packages = Vec::new();

    for line in input.lines() {
        let line = line.trim();

        // Skip header and separator lines
        if line.is_empty()
            || line.starts_with("Package")
            || line.starts_with("---")
            || line.starts_with('#')
        {
            continue;
        }

        // pip freeze format: name==version
        if let Some((name, version)) = line.split_once("==") {
            packages.push(Package {
                name: name.trim().to_string(),
                version: version.trim().to_string(),
            });
            continue;
        }

        // pip list column format: split on 2+ spaces (name may contain single spaces rarely)
        // The column separator is always multiple spaces or a tab.
        let parts: Vec<&str> = line.splitn(2, [' ', '\t']).collect();
        if parts.len() >= 2 {
            let name = parts[0].trim();
            // Version is the first non-empty token after the name
            let version = parts[1].split_whitespace().next().unwrap_or("").trim();
            if !name.is_empty() && !version.is_empty() {
                packages.push(Package {
                    name: name.to_string(),
                    version: version.to_string(),
                });
            }
        }
    }

    packages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pip_list_format() {
        let input = "Package    Version\n---------- -------\nnumpy      1.26.4\nrequests   2.31.0\n";
        let pkgs = parse_pip_list(input);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "numpy");
        assert_eq!(pkgs[0].version, "1.26.4");
        assert_eq!(pkgs[1].name, "requests");
        assert_eq!(pkgs[1].version, "2.31.0");
    }

    #[test]
    fn parses_freeze_format() {
        let input = "numpy==1.26.4\nrequests==2.31.0\n";
        let pkgs = parse_pip_list(input);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "numpy");
        assert_eq!(pkgs[1].name, "requests");
    }

    #[test]
    fn skips_empty_and_headers() {
        let input = "\n\nPackage Version\n------- -------\n\nnumpy 1.26.4\n";
        let pkgs = parse_pip_list(input);
        assert_eq!(pkgs.len(), 1);
    }
}
