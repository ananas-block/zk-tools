//! Compiler contract for the portable SIMD kernels.
/// Set this cfg only when the final binary receives the bounded Binaryen recipe.
pub const OPTIMIZED_WASM_CFG: &str = "--cfg zk_tools_wasm_opt";

pub fn has_field_postpass(args: &[&str]) -> bool {
    let option = |name: &str| {
        args.iter()
            .rev()
            .find_map(|arg| arg.strip_prefix(name))
            .and_then(|value| value.parse::<usize>().ok())
    };
    args.contains(&"--inlining")
        && args.contains(&"--inline-functions-with-loops")
        && option("--always-inline-max-function-size=").is_some_and(|size| size >= 10)
        && option("--one-caller-inline-max-function-size=") == Some(0)
        && option("--flexible-inline-max-function-size=") == Some(0)
        && args.iter().all(|arg| {
            matches!(
                *arg,
                "--inlining"
                    | "--inline-functions-with-loops"
                    | "--enable-simd"
                    | "--enable-threads"
                    | "--enable-bulk-memory"
                    | "--enable-mutable-globals"
                    | "--enable-sign-ext"
                    | "--enable-nontrapping-float-to-int"
                    | "--enable-multivalue"
                    | "--enable-reference-types"
                    | "-g"
            ) || arg.starts_with("--always-inline-max-function-size=")
                || arg.starts_with("--one-caller-inline-max-function-size=")
                || arg.starts_with("--flexible-inline-max-function-size=")
        })
}
