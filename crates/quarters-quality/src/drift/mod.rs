// SPDX-License-Identifier: GPL-3.0-or-later
//! Toolchain and dependency drift: a pinned version behind its upstream
//! release fails, so gates never run on stale tools. It runs on a schedule,
//! not in the gate, because an upstream release is not a defect in any one
//! pull request.

pub(crate) mod pins;
mod upstream;

use std::cmp::Ordering;
use std::path::Path;

/// Compare dotted numeric versions, ignoring a leading `v`. A pre-release of
/// the same numbers sorts before the release.
pub(crate) fn compare_versions(left: &str, right: &str) -> Ordering {
    fn parts(version: &str) -> (Vec<u64>, bool) {
        let version = version.trim().trim_start_matches('v');
        let (numbers, prerelease) = version
            .split_once('-')
            .map_or((version, false), |(numbers, _rest)| (numbers, true));
        let numbers = numbers
            .split('.')
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect();
        (numbers, prerelease)
    }
    let (left_numbers, left_pre) = parts(left);
    let (right_numbers, right_pre) = parts(right);
    let length = left_numbers.len().max(right_numbers.len());
    for index in 0..length {
        let ordering = left_numbers
            .get(index)
            .unwrap_or(&0)
            .cmp(right_numbers.get(index).unwrap_or(&0));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    right_pre.cmp(&left_pre)
}

/// One report line per pin behind upstream, or a single line saying all are
/// current; the boolean is whether anything is behind.
pub(crate) fn verdict(observed: &[(pins::Pin, String)]) -> (Vec<String>, bool) {
    let lines: Vec<String> = observed
        .iter()
        .filter(|(pin, latest)| compare_versions(&pin.current, latest) == Ordering::Less)
        .map(|(pin, latest)| {
            format!(
                "behind: {} {} in {}, upstream {latest}",
                pin.name, pin.current, pin.declared_in
            )
        })
        .collect();
    if lines.is_empty() {
        return (
            vec![format!(
                "current: all {} pins match their upstream releases",
                observed.len()
            )],
            false,
        );
    }
    (lines, true)
}

/// Run the drift check: exit 0 when current, 1 when behind, 2 on error.
pub(crate) fn run(root: &Path) -> u8 {
    let collected = match pins::collect(root) {
        Ok(collected) => collected,
        Err(error) => {
            eprintln!("quarters-quality drift: {error}");
            return 2;
        }
    };
    let mut observed = Vec::with_capacity(collected.len());
    for pin in collected {
        match upstream::latest(&pin.upstream, &pin.current) {
            Ok(latest) => observed.push((pin, latest)),
            Err(error) => {
                eprintln!("quarters-quality drift: {error}");
                return 2;
            }
        }
    }
    let (lines, behind) = verdict(&observed);
    for line in lines {
        println!("{line}");
    }
    u8::from(behind)
}

#[cfg(test)]
mod tests;
