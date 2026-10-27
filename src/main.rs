//! The entry point of the Frut interpreter.
//!
//! CLI contract (shared by all Frut backends):
//!   frut [OPTIONS] [ENTRY]
//!
//!   ENTRY                     path to the entry .ft file
//!                             default: <project>/main.ft
//!   -p, --project <DIR>       project root; default: ENTRY's directory
//!   -n, --name <NAME>         this library's import name; default: self
//!   -l, --lib <NAME>=<PATH>   mount PATH as library NAME (repeatable);
//!                             std=<PATH> overrides the embedded std
//!   -f, --format <FORMAT>     output format: text (default) | json
//!       --no-std              do not mount the standard library
//!       --print-std           unpack the embedded std to disk and print its
//!                             path (for tools such as frut_lsp / fpm)
//!       --version             print the backend version
//!   -h, --help
//!
//! The standard library is embedded into the binary (see
//! [`frut_interp::loader::EMBEDDED_STD`]) and mounted as `std` by default.

use colored::Colorize;
use frut_interp::interpreter::Interpreter;
use frut_interp::loader::{build_tree, find_std, unpack_embedded_std, LibMount, ProjectMount};
use frut_lib::parse_code;
use std::path::PathBuf;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Parsed CLI options
struct Options {
    entry: Option<PathBuf>,
    project: Option<PathBuf>,
    name: String,
    libs: Vec<LibMount>,
    format: OutputFormat,
    no_std: bool,
}

enum OutputFormat {
    Text,
    Json,
}

fn usage() -> String {
    "usage: frut [-p <dir>] [-n <name>] [-e <file>] [-l <name>=<path>] [-f text|json] [--no-std] [--print-std] <file.ft>".to_string()
}

fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut opts = Options {
        entry: None,
        project: None,
        name: "self".to_string(),
        libs: Vec::new(),
        format: OutputFormat::Text,
        no_std: false,
    };

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            "--version" => {
                println!("frut {VERSION}");
                std::process::exit(0);
            }
            "-p" | "--project" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    return Err(format!("{arg} requires a value"));
                };
                opts.project = Some(PathBuf::from(v));
            }
            "-n" | "--name" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    return Err(format!("{arg} requires a value"));
                };
                opts.name = v.clone();
            }
            "-e" | "--entry" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    return Err(format!("{arg} requires a value"));
                };
                if opts.entry.is_some() {
                    return Err("multiple entry files given".to_string());
                }
                opts.entry = Some(PathBuf::from(v));
            }
            "-l" | "--lib" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    return Err(format!("{arg} requires a value"));
                };
                let Some((name, path)) = v.split_once('=') else {
                    return Err(format!("--lib expects <NAME>=<PATH>, got `{v}`"));
                };
                if name.is_empty() || path.is_empty() {
                    return Err(format!("--lib expects <NAME>=<PATH>, got `{v}`"));
                }
                opts.libs.push(LibMount::new(name, path));
            }
            "-f" | "--format" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    return Err(format!("{arg} requires a value"));
                };
                opts.format = match v.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    other => {
                        return Err(format!(
                            "unknown output format `{other}` (expected text|json)"
                        ))
                    }
                };
            }
            "--no-std" => opts.no_std = true,
            other => {
                if other.starts_with('-') {
                    return Err(format!("unknown option `{other}`"));
                }
                if opts.entry.is_some() {
                    return Err("multiple entry files given".to_string());
                }
                opts.entry = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    Ok(opts)
}

fn display_error(error: &frut_lib::ErrorReport) -> String {
    use std::fmt::Write;

    let mut result = String::with_capacity(256);
    let offset = error.position.column.saturating_sub(1);
    let span = if error.position.length > 0 {
        error.position.length
    } else {
        1
    };

    let _ = write!(
        result,
        "{} {}\n {} {}:{}:{}\n   {}\n{} {}{}\n   {}{}{} {}",
        format!("[E{:04}]", error.code.as_u32()).red().bold(),
        error.error_type.to_string().bold(),
        "-->".blue().bold(),
        error.position.file,
        error.position.line,
        error.position.column,
        "| ".blue().bold(),
        error.position.line.to_string().bright_blue(),
        "| ".blue().bold(),
        error.code_snippet,
        "| ".blue().bold(),
        " ".repeat(offset),
        "^".repeat(span).red().bold(),
        error.message.red().bold()
    );

    result
}

/// Escape a string for embedding into a JSON string literal
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Render a batch of errors as a JSON object (for fpm/LSP/CI consumption)
fn errors_to_json(errors: &[frut_lib::ErrorReport]) -> String {
    let mut out = String::from("{\"success\":false,\"errors\":[");
    for (i, e) in errors.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"code\":{},\"type\":\"{}\",\"message\":\"{}\",\"file\":\"{}\",\"line\":{},\"column\":{},\"snippet\":\"{}\"}}",
            e.code.as_u32(),
            json_escape(&e.error_type.to_string()),
            json_escape(&e.message),
            json_escape(&e.position.file),
            e.position.line,
            e.position.column,
            json_escape(&e.code_snippet),
        ));
    }
    out.push_str("]}");
    out
}

/// Report errors according to the selected output format and exit
fn report_errors(
    format: &OutputFormat,
    errors: &[frut_lib::ErrorReport],
    header: &str,
) -> ExitCode {
    match format {
        OutputFormat::Text => {
            for error in errors {
                println!("{}", display_error(error));
            }
            println!("{}", header.bold().red());
        }
        OutputFormat::Json => {
            println!("{}", errors_to_json(errors));
        }
    }
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // `--print-std` is handled before entry resolution: it must work without
    // a project or an entry file.
    if args.iter().any(|arg| arg == "--print-std") {
        return match unpack_embedded_std() {
            Ok(path) => {
                println!("{}", path.display());
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("{}: {}", "error".bold().red(), message);
                ExitCode::FAILURE
            }
        };
    }

    let opts = match parse_args(&args) {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("{}: {}", "error".bold().red(), msg);
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };

    let entry = match opts
        .entry
        .clone()
        .or_else(|| opts.project.as_ref().map(|p| p.join("main.ft")))
    {
        Some(entry) => entry,
        None => {
            eprintln!("{}: no entry file given", "error".bold().red());
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };
    let entry = if !entry.is_absolute() {
        if let Some(project) = &opts.project {
            project.join(entry)
        } else {
            entry
        }
    } else {
        entry
    };

    let project_dir = opts
        .project
        .clone()
        .or_else(|| entry.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    if entry.extension().map(|e| e != "ft").unwrap_or(true) {
        eprintln!(
            "{}: The file must have an extension .ft",
            "error".bold().red()
        );
        return ExitCode::from(2);
    }

    let content = match std::fs::read_to_string(&entry) {
        Ok(str) => str,
        Err(_) => {
            eprintln!(
                "{}: Failed to read file `{}`",
                "error".bold().red(),
                entry.display()
            );
            return ExitCode::from(2);
        }
    };

    let entry_display = entry.to_string_lossy().to_string();

    let parse_result = parse_code(&content, entry_display.clone());
    if !parse_result.is_success() {
        return report_errors(
            &opts.format,
            &parse_result.errors.errors,
            &format!(
                "error: could not parse file due to {} previous error{}",
                parse_result.errors.len(),
                if parse_result.errors.len() > 1 {
                    "s"
                } else {
                    ""
                }
            ),
        );
    }

    let mut libs: Vec<LibMount> = opts.libs.clone();
    let has_std_mount = libs.iter().any(|l| l.name == "std");
    if !opts.no_std && !has_std_mount {
        match find_std(Some(&project_dir)) {
            Some(std_path) => libs.push(LibMount::new("std", std_path)),
            None => libs.push(LibMount::embedded_std()),
        }
    }

    let project_mount = ProjectMount::Dir(project_dir.clone());
    let tree = build_tree(project_mount, &opts.name, &libs);
    if !tree.errors.is_empty() {
        return report_errors(
            &opts.format,
            &tree.errors.errors,
            "error: could not load project sources",
        );
    }

    let mut interpreter = Interpreter::with_tree(entry_display.clone(), content.clone(), tree.root);

    let mut analyzer = Interpreter::create_semantic_analyzer_with_module(
        entry_display.clone(),
        content.clone(),
        interpreter.get_module(),
    );
    if let Err(semantic_errors) = analyzer.analyze(&parse_result.statements) {
        return report_errors(
            &opts.format,
            &semantic_errors.errors,
            &format!(
                "error: Semantic analysis failed with {} error{}",
                semantic_errors.len(),
                if semantic_errors.len() > 1 { "s" } else { "" }
            ),
        );
    }

    match interpreter.interpret(&parse_result.statements) {
        Ok(_) => {
            if matches!(opts.format, OutputFormat::Json) {
                println!("{{\"success\":true,\"errors\":[]}}");
            } else {
                println!(
                    "{}: Successfully executed `{}`",
                    "info".bold().green(),
                    entry_display
                );
            }
            ExitCode::SUCCESS
        }
        Err(runtime_error) => report_errors(&opts.format, &[runtime_error], "error: runtime error"),
    }
}
