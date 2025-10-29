//! The entry point of the Frut interpreter.

use colored::Colorize;
use frut_lib::{parse_files, File as FrutFile, ErrorReport, Statement, StatementKind};
use frut_interp::interpreter::Interpreter;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn display_error(error: &ErrorReport) -> String {
    use std::fmt::Write;
    
    let mut result = String::with_capacity(256);
    let offset = error.position.column.saturating_sub(1);
    let span = if error.position.length > 0 { error.position.length } else { 1 };
    
    let _ = write!(
        result,
        "{} {}\n {} {}:{}:{}\n   {}\n{:2} {}{}\n   {}{}{}",
        format!("[E{:04}]", error.code.clone() as u32).red().bold(),
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
        format!("{} {}", "^".repeat(span).red().bold(), error.message.red().bold())
    );
    
    result
}

/// The entry point of the Frut interpreter.
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("{}: `frut <path_to_file.ft>`", "usage".bold().yellow());
        return;
    }

    let file_path = &args[1];

    if !file_path.ends_with(".ft") {
        println!(
            "{}: The file must have an extension .ft",
            "error".bold().red()
        );
        return;
    }

    let content = match fs::read_to_string(file_path) {
        Ok(str) => str,
        Err(_) => {
            println!(
                "{}: Failed to read file `{}`",
                "error".bold().red(),
                file_path
            );
            return;
        }
    };

    let entry_dir = Path::new(file_path).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    let mut files: Vec<FrutFile> = Vec::new();
    
    fn collect_ft_files(dir: &Path, out: &mut Vec<FrutFile>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for ent in entries.flatten() {
                let path = ent.path();
                if path.is_dir() {
                    collect_ft_files(&path, out);
                } else if path.extension().map_or(false, |ext| ext == "ft") {
                    if let Ok(code) = fs::read_to_string(&path) {
                        out.push(FrutFile { 
                            path: path.to_string_lossy().to_string(), 
                            code, 
                            ast: None 
                        });
                    }
                }
            }
        }
    }
    
    collect_ft_files(&entry_dir, &mut files); 
    
    if !files.iter().any(|f| f.path == *file_path) {
        files.push(FrutFile { path: file_path.to_string(), code: content.clone(), ast: None });
    }

    let project_result = parse_files(files);
    if !project_result.errors.is_empty() {
        for error in &project_result.errors.errors {
            println!("{}", display_error(error));
        }
        println!(
            "{}: could not parse project due to {} previous error{}",
            "error".red().bold(),
            project_result.errors.len(),
            if project_result.errors.len() > 1 { "s" } else { "" }
        );
        return;
    }

    let mut project = project_result.project;
    
    for file in &mut project.files {
        let mut analyzer = Interpreter::create_semantic_analyzer(file.path.clone(), file.code.clone());
        if let Some(ast) = &file.ast {
            for stmt in ast.iter() {
                if let StatementKind::Import { path, kind } = &stmt.kind {
                    if frut_std::has_native_module(path) {
                        if let Some(sigs) = frut_std::native_signatures_for(path) {
                            match kind {
                                frut_lib::ImportKind::Wildcard => {
                                    for fs in sigs.iter() {
                                        let _ = analyzer.predeclare_function(fs.name.clone(), fs.params.clone(), fs.ret.clone());
                                    }
                                }
                                frut_lib::ImportKind::Single(name) => {
                                    for fs in sigs.iter().filter(|fs| &fs.name == name) {
                                        let _ = analyzer.predeclare_function(fs.name.clone(), fs.params.clone(), fs.ret.clone());
                                    }
                                }
                                frut_lib::ImportKind::Group(names) => {
                                    for n in names.iter() {
                                        for fs in sigs.iter().filter(|fs| &fs.name == n) {
                                            let _ = analyzer.predeclare_function(fs.name.clone(), fs.params.clone(), fs.ret.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Err(semantic_errors) = analyzer.analyze(ast) {
                println!("{}: Semantic analysis failed with {} error{}:",
                    "error".red().bold(),
                    semantic_errors.len(),
                    if semantic_errors.len() > 1 { "s" } else { "" }
                );
                for error in &semantic_errors.errors {
                    println!("{}", display_error(error));
                }
                return;
            }
        }
    }

    let mut combined: Vec<Statement> = Vec::new();
    
    for f in project.files.iter() {
        if let Some(ast) = &f.ast {
            if f.path == file_path.as_str() {
                combined.extend(ast.iter().cloned());
            } else {
                if !f.path.starts_with("std/") && !f.path.contains("/std/") {
                    for stmt in ast.iter() {
                        if matches!(&stmt.kind, StatementKind::VariableDeclaration { .. } | StatementKind::FunctionDeclaration { .. }) {
                            combined.insert(
                                combined.iter().position(|s| !matches!(s.kind, StatementKind::VariableDeclaration { .. } | StatementKind::FunctionDeclaration { .. })).unwrap_or(combined.len()),
                                stmt.clone()
                            );
                        }
                    }
                }
            }
        }
    }

    let mut interpreter = Interpreter::new(file_path.to_string(), content.clone());

    let mut imported_native: std::collections::BTreeMap<String, Option<std::collections::BTreeSet<String>>> = std::collections::BTreeMap::new();
    for f in project.files.iter() {
        if let Some(ast) = &f.ast {
            for stmt in ast.iter() {
                if let StatementKind::Import { path, kind } = &stmt.kind {
                    if frut_std::has_native_module(path) {
                        let key = path.join("/");
                        match kind {
                            frut_lib::ImportKind::Wildcard => {
                                imported_native.insert(key, None);
                            }
                            frut_lib::ImportKind::Single(name) => {
                                let entry = imported_native.entry(key).or_insert_with(|| Some(std::collections::BTreeSet::new()));
                                if let Some(set) = entry.as_mut() { set.insert(name.clone()); } else { /* wildcard already present */ }
                            }
                            frut_lib::ImportKind::Group(names) => {
                                let entry = imported_native.entry(key).or_insert_with(|| Some(std::collections::BTreeSet::new()));
                                if let Some(set) = entry.as_mut() {
                                    for n in names { set.insert(n.clone()); }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !imported_native.is_empty() {
        let modules: Vec<(String, Option<Vec<String>>)> = imported_native.into_iter().map(|(k, opt)| {
            match opt {
                None => (k, None),
                Some(set) => (k, Some(set.into_iter().collect())),
            }
        }).collect();
        frut_std::register_native_modules(interpreter.environment_mut(), &modules);
    }
    match interpreter.interpret(&combined) {
        Ok(_) => {
            println!(
                "{}: Successfully executed `{}`",
                "info".bold().green(),
                file_path
            );
        }
        Err(runtime_error) => {
            println!("{}", display_error(&runtime_error));
        }
    }
    return;
}
