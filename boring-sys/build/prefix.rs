use crate::{config::Config, run_command};
use std::{fs, io::Write, path::PathBuf, process::Command};

/// Prefix applied to all BoringSSL symbols so they don't collide with OpenSSL.
///
const SYMBOL_PREFIX: &str = "BSSL";

/// Bindgen callback that rewrites link names to use the prefixed symbol.
///
/// C symbol `SSL_new` → Rust binding `#[link_name = "BSSL_SSL_new"]`.
#[derive(Debug)]
pub struct SymbolPrefixCallbacks;

impl bindgen::callbacks::ParseCallbacks for SymbolPrefixCallbacks {
    fn generated_link_name_override(
        &self,
        item_info: bindgen::callbacks::ItemInfo<'_>,
    ) -> Option<String> {
        Some(format!("{SYMBOL_PREFIX}_{}", item_info.name))
    }
}

/// Rewrite all global symbols in libssl.a/libcrypto.a to use the S2N_BSSL_ prefix.
///
/// This runs `nm` to list symbols and `objcopy --redefine-syms` to edit the archives
/// in-place, so they can safely coexist with other {libssl,libcrypto} in the process.
pub fn apply_symbol_prefixes(config: &Config) {
    // CMake output directories where libssl.a/libcrypto.a are expected.
    let static_lib_dirs = [
        config.out_dir.join("build"),
        config.out_dir.join("build").join("ssl"),
        config.out_dir.join("build").join("crypto"),
    ];

    let static_libs: Vec<PathBuf> = static_lib_dirs
        .iter()
        .flat_map(|dir| {
            ["libssl.a", "libcrypto.a"]
                .into_iter()
                .map(move |file| dir.join(file))
        })
        .filter(|path| path.exists())
        .collect();

    if static_libs.is_empty() {
        eprintln!("warning: no libssl.a/libcrypto.a archives found to prefix");
        return;
    }

    // 1. Use `nm` to list global symbols in the archives.
    let nm_output = run_command(Command::new("nm").args(&static_libs))
        .expect("failed to run `nm` on BoringSSL archives");

    let mut mappings: Vec<String> = String::from_utf8_lossy(&nm_output.stdout)
        .lines()
        // Keep only global symbol types we care about.
        .filter(|line| {
            [" T ", " D ", " B ", " C ", " R ", " W "]
                .iter()
                .any(|marker| line.contains(marker))
        })
        // Symbol name is usually the 3rd column.
        .filter_map(|line| line.split_whitespace().nth(2).map(str::to_owned))
        // Skip leading-underscore internals.
        .filter(|sym| !sym.starts_with('_'))
        // Compose `old new` mapping line: `sym S2N_BSSL_sym`.
        .map(|sym| format!("{sym} {SYMBOL_PREFIX}_{sym}"))
        .collect();

    mappings.sort();
    mappings.dedup();

    let mapping_file = config.out_dir.join("redefine_syms.txt");
    let mut f = fs::File::create(&mapping_file)
        .expect("failed to create redefine_syms.txt for symbol prefixing");

    for mapping in &mappings {
        writeln!(f, "{mapping}").expect("failed to write symbol mapping");
    }
    f.flush().expect("failed to flush symbol mapping file");

    // 2. Use `objcopy` to apply the mapping to each archive in-place.
    for static_lib in &static_libs {
        run_command(
            Command::new("objcopy")
                .arg(format!("--redefine-syms={}", mapping_file.display()))
                .arg(static_lib),
        )
        .expect("failed to run `objcopy` to redefine symbols");
    }
}
