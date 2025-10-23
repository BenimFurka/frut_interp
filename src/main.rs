//! The entry point of the Frut interpreter.

use colored::Colorize;
use frut_lib::{parse_files, File as FrutFile, ErrorReport, Statement, StatementKind};
use frut_interp::interpreter::Interpreter;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn display_error(error: &ErrorReport) -> String {
    let mut result = String::new();

    result.push_str(&format!("{} {}", format!("[E{:04}]", error.code.clone() as u32).red().bold(), error.error_type.to_string().bold()));

    result.push_str(&format!("\n {} {}:{}:{}", "-->".blue().bold(), error.position.file, error.position.line, error.position.column));

    let code_snippet = &error.code_snippet;
    result.push_str(&format!("\n   {}", "| ".blue().bold()));
    result.push_str(&format!("\n{:2} {}{}", error.position.line.to_string().black(), "| ".blue().bold(), code_snippet));
    result.push_str(&format!("\n   {}", "| ".blue().bold()));

    let offset = error.position.column.saturating_sub(1);
    for _ in 0..offset {
        result.push(' ');
    }
    let span = if error.position.length > 0 { error.position.length } else { 1 };
    let caret_str = "^".repeat(span).red().bold();
    result.push_str(&format!("{} {}", caret_str, error.message.red().bold()));

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
    fn collect_ft_files(dir: &Path, out: &mut Vec<(String, String)>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for ent in entries.flatten() {
                let path = ent.path();
                if path.is_dir() {
                    collect_ft_files(&path, out);
                } else if let Some(ext) = path.extension() {
                    if ext == "ft" {
                        if let Ok(code) = fs::read_to_string(&path) {
                            out.push((path.to_string_lossy().to_string(), code));
                        }
                    }
                }
            }
        }
    }
    let mut collected: Vec<(String, String)> = Vec::new();
    collect_ft_files(&entry_dir, &mut collected);
    if !collected.iter().any(|(p, _)| p == file_path) {
        collected.push((file_path.to_string(), content.clone()));
    }
    for (p, c) in collected.into_iter() {
        files.push(FrutFile { path: p, code: c, ast: None });
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
    let mut main_statements: Vec<Statement> = Vec::new();
    for f in project.files.iter() {
        if f.path == file_path.as_str() {
            if let Some(ast) = &f.ast {
                main_statements = ast.clone();
            }
        } else {
            if let Some(ast) = &f.ast {
                for stmt in ast.iter() {
                    if let StatementKind::VariableDeclaration { .. } = &stmt.kind {
                        combined.push(stmt.clone());
                    }
                }
                for stmt in ast.iter() {
                    if let StatementKind::FunctionDeclaration { .. } = &stmt.kind {
                        combined.push(stmt.clone());
                    }
                }
            }
        }
    }
    combined.extend(main_statements.into_iter());

    let mut interpreter = Interpreter::new(file_path.to_string(), content.clone());
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
