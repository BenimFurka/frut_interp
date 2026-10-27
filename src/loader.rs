//! Autonomous source loader for the Frut interpreter backend.

use frut_lib::{parse_code, ErrorCollection, ErrorReport, File, Module};
use std::fs;
use std::path::{Path, PathBuf};

/// The standard library embedded into the binary at compile time
pub const EMBEDDED_STD: &[(&str, &str)] = &[
    ("io", include_str!("../std/io.ft")),
    ("math", include_str!("../std/math.ft")),
    ("option", include_str!("../std/option.ft")),
    ("strings", include_str!("../std/strings.ft")),
    ("vec", include_str!("../std/vec.ft")),
    ("bytes", include_str!("../std/bytes.ft")),
    ("fs", include_str!("../std/fs.ft")),
    ("time", include_str!("../std/time.ft")),
    ("process", include_str!("../std/process.ft")),
    ("native.io", include_str!("../std/native/io.ft")),
    ("native.math", include_str!("../std/native/math.ft")),
    ("native.strings", include_str!("../std/native/strings.ft")),
    ("native.vec", include_str!("../std/native/vec.ft")),
    ("native.bytes", include_str!("../std/native/bytes.ft")),
    ("native.fs", include_str!("../std/native/fs.ft")),
    ("native.time", include_str!("../std/native/time.ft")),
    ("native.process", include_str!("../std/native/process.ft")),
];

/// Build the embedded `std` module tree
pub fn build_embedded_std(errors: &mut ErrorCollection) -> Module {
    let mut std = Module::new("std".to_string());
    for (qualified, source) in EMBEDDED_STD {
        let (module_path, file_name) = match qualified.rsplit_once('.') {
            Some((module, file)) => (Some(module), file),
            None => (None, *qualified),
        };
        let ast = collect_parse_result(
            parse_code(source, format!("<std>/{}.ft", qualified.replace('.', "/"))),
            errors,
        );
        let file = File {
            name: file_name.to_string(),
            code: (*source).to_string(),
            ast,
        };
        match module_path {
            Some(module) => {
                let mut cur = &mut std;
                for seg in module.split('.') {
                    if cur.find_submodule_mut(seg).is_none() {
                        cur.add_submodule(Module::new(seg.to_string()));
                    }
                    cur = cur.find_submodule_mut(seg).expect("submodule just added");
                }
                cur.add_file(file);
            }
            None => std.add_file(file),
        }
    }
    std
}

/// A library mount: a name (used in imports as `name.x.y.z`) and the
/// directory containing its `.ft` sources
#[derive(Debug, Clone)]
pub struct LibMount {
    /// Top-level module name, e.g. `std`, `mylib`, or the project's own name
    pub name: String,
    /// Directory to scan for `.ft` files
    pub path: PathBuf,
}

impl LibMount {
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
        }
    }

    /// Mount the std library embedded in this binary (no directory needed)
    pub fn embedded_std() -> Self {
        Self {
            name: "std".to_string(),
            path: PathBuf::new(),
        }
    }

    /// Whether this mount refers to the embedded std
    pub fn is_embedded_std(&self) -> bool {
        self.name == "std" && self.path.as_os_str().is_empty()
    }
}

/// How the project (the entry point's library) is mounted
#[derive(Debug, Clone)]
pub enum ProjectMount {
    /// Scan the whole project directory (multi-file project)
    Dir(PathBuf),
    /// Mount only the entry file (isolated single-file run)
    SingleFile { path: PathBuf, name: String },
}

/// Result of building a module tree
#[derive(Debug)]
pub struct TreeBuild {
    pub root: Module,
    pub errors: ErrorCollection,
}

impl TreeBuild {
    fn empty() -> Self {
        Self {
            root: Module::new("root".to_string()),
            errors: ErrorCollection::new(),
        }
    }
}

/// Build the module tree: `root -> { <project>, std?, <libs>... }`
///
/// - `project` - the entry library, mounted under `project_name`
///   (default `self` for backwards compatibility with existing imports).
/// - `libs` - additional libraries mounted at the top level under their names.
///   A lib named `std` replaces the implicit std lookup
pub fn build_tree(project: ProjectMount, project_name: &str, libs: &[LibMount]) -> TreeBuild {
    let mut build = TreeBuild::empty();

    match project {
        ProjectMount::Dir(dir) => {
            let mut top = Module::new(project_name.to_string());
            if dir.is_dir() {
                scan_dir(&dir, &mut top, &mut build.errors);
            }
            build.root.add_submodule(top);
        }
        ProjectMount::SingleFile { path, name } => {
            let mut top = Module::new(project_name.to_string());
            mount_single_file(&path, &name, &mut top, &mut build.errors);
            build.root.add_submodule(top);
        }
    }

    for lib in libs {
        if lib.is_embedded_std() {
            let std = build_embedded_std(&mut build.errors);
            build.root.add_submodule(std);
            continue;
        }
        let mut top = Module::new(lib.name.clone());
        if lib.path.is_dir() {
            scan_dir(&lib.path, &mut top, &mut build.errors);
        }
        build.root.add_submodule(top);
    }

    build
}

/// Mount a single file into `module` under the given (extension-less) name
fn mount_single_file(path: &Path, name: &str, module: &mut Module, errors: &mut ErrorCollection) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    let parse_result = parse_code(&content, path.to_string_lossy().to_string());
    let ast = collect_parse_result(parse_result, errors);
    module.add_file(File {
        name: name.to_string(),
        code: content,
        ast,
    });
}

/// Recursively scan a directory, adding `.ft` files (name without extension)
fn scan_dir(dir: &Path, module: &mut Module, errors: &mut ErrorCollection) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.')
                || name == "target"
                || name == "build"
                || name == "node_modules"
            {
                continue;
            }
        }

        if path.is_dir() {
            dirs.push(path);
        } else if let Some(ext) = path.extension() {
            if ext == "ft" {
                files.push(path);
            }
        }
    }

    dirs.sort();
    files.sort();

    for file_path in files {
        let Ok(content) = fs::read_to_string(&file_path) else {
            continue;
        };
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.strip_suffix(".ft").unwrap_or(n).to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let parse_result = parse_code(&content, file_path.to_string_lossy().to_string());
        let ast = collect_parse_result(parse_result, errors);
        module.add_file(File {
            name: filename,
            code: content,
            ast,
        });
    }

    for dir_path in dirs {
        let Some(dir_name) = dir_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let mut submodule = Module::new(dir_name.to_string());
        scan_dir(&dir_path, &mut submodule, errors);
        module.add_submodule(submodule);
    }
}

/// Turn a parse result into an optional AST, collecting errors
fn collect_parse_result(
    parse_result: frut_lib::ParseResult,
    errors: &mut ErrorCollection,
) -> Option<Vec<frut_lib::ast::Statement>> {
    if parse_result.is_success() {
        Some(parse_result.statements)
    } else {
        for e in &parse_result.errors.errors {
            errors.add_error(e.clone());
        }
        None
    }
}

/// Unpack [`EMBEDDED_STD`] into a per-user cache directory and return its
/// path.
pub fn unpack_embedded_std() -> Result<PathBuf, String> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".cache"))
        })
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from))
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("frut").join("std").join(format!(
        "{}-{}",
        env!("CARGO_PKG_VERSION"),
        EMBEDDED_STD.len()
    ));
    if dir.join("io.ft").is_file() {
        return Ok(dir);
    }

    let staging = dir.with_extension(format!("tmp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    for (qualified, source) in EMBEDDED_STD {
        let path = staging.join(format!("{}.ft", qualified.replace('.', "/")));
        let write = path
            .parent()
            .map(|parent| fs::create_dir_all(parent))
            .unwrap_or(Ok(()))
            .and_then(|()| fs::write(&path, source));
        if let Err(e) = write {
            let _ = fs::remove_dir_all(&staging);
            return Err(format!("cannot write {}: {}", path.display(), e));
        }
    }
    match fs::rename(&staging, &dir) {
        Ok(()) => Ok(dir),
        Err(_) if dir.join("io.ft").is_file() => {
            let _ = fs::remove_dir_all(&staging);
            Ok(dir)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            Err(format!("cannot unpack std into {}: {}", dir.display(), e))
        }
    }
}

/// Locate an *external* standard library directory to override the embedded
/// one
pub fn find_std(_start: Option<&Path>) -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("FRUT_STD_PATH") {
        let p = PathBuf::from(env_path);
        if p.is_dir() {
            return Some(p);
        }
    }
    None
}

/// Re-export for main.rs convenience: report a fatal loader error as an
/// `ErrorReport` (e.g. missing entry file)
pub fn loader_error(message: String) -> ErrorReport {
    ErrorReport::simple(
        frut_lib::ErrorType::RuntimeError,
        message,
        "loader".to_string(),
        1,
        1,
        String::new(),
    )
}
