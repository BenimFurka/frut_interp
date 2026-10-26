//! Interpreter for the Frut
//!
//! Executes parsed AST nodes and produces runtime values.
#![allow(clippy::result_large_err)]

use frut_lib::ast::{Expression, ExpressionKind, Statement, StatementKind};
use frut_lib::resolver::{ImportResolver, ResolvedImport};
use frut_lib::types::Type;
use frut_lib::value::{RuntimeEnvironment, Value};
use frut_lib::{HashMap, Module};

/// Result type for interpreter operations
pub enum InterpreterResult {
    Ok(()),
    Return(Value),
    Break,
    Err(frut_lib::ErrorReport),
}

const MAX_RECURSION_DEPTH: u32 = 512;

/// Wrap a `Vec<Statement>` body into the `Arc`
fn alloc_to_arc(body: &[Statement]) -> std::sync::Arc<Vec<Statement>> {
    std::sync::Arc::new(body.to_vec())
}

/// Render bytes the same way frut_lib's `Display for Value` does:
/// `bytes[0a ff 00]`
fn display_bytes(b: &[u8]) -> String {
    let mut out = String::with_capacity(8 + b.len() * 3);
    out.push_str("bytes[");
    for (i, byte) in b.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out.push(']');
    out
}

/// Interpreter for the Frut
pub struct Interpreter {
    filename: String,
    source: String,
    environment: RuntimeEnvironment,
    recursion_depth: u32,
    current_function: Vec<String>,
    module: Module,
    loaded_files: Vec<String>,
}

impl<'m> Interpreter {
    /// Create a semantic analyzer for a single file (without a module tree)
    pub fn create_semantic_analyzer(
        filename: String,
        source: String,
    ) -> frut_lib::semantic::SemanticAnalyzer<'static> {
        frut_lib::semantic::SemanticAnalyzer::new(filename, source)
    }

    /// Create a semantic analyzer with the full module tree
    pub fn create_semantic_analyzer_with_module(
        filename: String,
        source: String,
        module: &'m Module,
    ) -> frut_lib::semantic::SemanticAnalyzer<'m> {
        frut_lib::semantic::SemanticAnalyzer::with_module_ref(filename, source, module)
    }

    /// Create a new interpreter from an externally built module tree
    pub fn with_tree(filename: String, source: String, module: Module) -> Self {
        let mut environment = RuntimeEnvironment::new();

        let mut registry = frut_lib::NativeRegistry::new();
        crate::natives::register_host_natives(&mut registry);
        registry.bind_all(&mut environment);

        let mut interpreter = Self {
            filename,
            source,
            environment,
            recursion_depth: 0,
            current_function: Vec::new(),
            module,
            loaded_files: Vec::new(),
        };

        interpreter.load_all_std();

        interpreter
    }

    /// Get the module tree (for semantic analysis)
    pub fn get_module(&self) -> &Module {
        &self.module
    }

    /// Interpret a list of statements
    pub fn interpret(&mut self, statements: &[Statement]) -> Result<(), frut_lib::ErrorReport> {
        for statement in statements {
            match self.interpret_statement(statement) {
                InterpreterResult::Ok(_) => {}
                InterpreterResult::Return(_) => {
                    let pos = statement.pos.clone();
                    return Err(self.create_error(
                        frut_lib::ErrorType::RuntimeError,
                        "Cannot return from top-level".to_string(),
                        &pos,
                    ));
                }
                InterpreterResult::Break => {
                    let pos = statement.pos.clone();
                    return Err(self.create_error(
                        frut_lib::ErrorType::RuntimeError,
                        "Cannot break outside of a loop".to_string(),
                        &pos,
                    ));
                }
                InterpreterResult::Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Create an error report with position information
    fn create_error(
        &self,
        error_type: frut_lib::ErrorType,
        message: String,
        pos: &frut_lib::Position,
    ) -> frut_lib::ErrorReport {
        frut_lib::ErrorReport::with_file(
            error_type,
            message,
            self.filename.clone(),
            pos.line,
            pos.column,
            pos.offset,
            pos.length,
            self.extract_code_snippet(pos.line),
        )
    }

    fn extract_code_snippet(&self, line: usize) -> String {
        if line == 0 {
            return "".to_string();
        }
        let lines: Vec<&str> = self.source.lines().collect();
        if line > 0 && line <= lines.len() {
            lines[line - 1].to_string()
        } else {
            "".to_string()
        }
    }

    /// The fully-qualified name of a file within a module, e.g. "std.io"
    fn qualified_file_path(module_name: &str, file_name: &str) -> String {
        format!("{module_name}.{file_name}")
    }

    /// Whether a fully-qualified file path (e.g. "std.io") was already executed
    fn is_file_loaded(&self, qualified: &str) -> bool {
        self.loaded_files.iter().any(|f| f == qualified)
    }

    fn mark_loaded(&mut self, qualified: String) {
        if !self.loaded_files.contains(&qualified) {
            self.loaded_files.push(qualified);
        }
    }

    /// Pre-execute all `std` module files so that `import std.io.*` resolves to
    /// real Frut functions
    fn load_all_std(&mut self) {
        let std_module = self
            .module
            .submodules
            .iter()
            .find(|m| m.name == "std")
            .cloned();
        if let Some(std_module) = std_module {
            self.load_module_files(&std_module, "std");
        }
    }

    fn load_module_files(&mut self, module: &Module, prefix: &str) {
        for file in &module.files {
            let qualified = Self::qualified_file_path(prefix, &file.name);
            let _ = self.execute_file_if_needed(&qualified);
        }
        for sub in &module.submodules {
            let sub_prefix = if prefix.is_empty() {
                sub.name.clone()
            } else {
                format!("{}.{}", prefix, sub.name)
            };
            self.load_module_files(sub, &sub_prefix);
        }
    }

    /// Execute a file by qualified name (e.g. "std.io") if not loaded yet
    fn execute_file_if_needed(&mut self, qualified: &str) -> Result<(), frut_lib::ErrorReport> {
        if self.is_file_loaded(qualified) {
            return Ok(());
        }
        let ast = {
            let file = self.find_file(qualified).ok_or_else(|| {
                self.create_error(
                    frut_lib::ErrorType::UndefinedVariable(qualified.to_string()),
                    format!("File '{qualified}' not found in module tree"),
                    &frut_lib::Position::new(self.filename.clone(), 1, 1, 0, 1),
                )
            })?;
            file.ast.clone().unwrap_or_default()
        };
        self.mark_loaded(qualified.to_string());

        let module_domain = qualified.to_string();
        let prev_module = self.environment.get_current_module().to_string();
        self.environment.set_current_module(module_domain.clone());

        for statement in &ast {
            if let InterpreterResult::Err(e) = self.interpret_statement(statement) {
                self.environment.set_current_module(prev_module);
                return Err(e);
            }
        }

        let exported = self.environment.module_symbols(&module_domain);
        for (name, _) in exported {
            self.environment
                .define_alias(&module_domain, name.clone(), name);
        }

        self.environment.set_current_module(prev_module);
        Ok(())
    }

    /// Find a file by its qualified name (e.g. "std.io")
    fn find_file(&self, qualified: &str) -> Option<&frut_lib::File> {
        let mut parts = qualified.split('.');
        let first = parts.next()?;
        let module = self.module.find_submodule(first)?;
        let rest: Vec<&str> = parts.collect();
        find_file_in(module, &rest)
    }

    /// Execute `statements` in a fresh scope, returning `Some(signal)` when a
    /// `return`, `break`, or error must propagate out of the enclosing block,
    /// and `None` when execution completed normally
    fn interpret_scoped_block(&mut self, statements: &[Statement]) -> Option<InterpreterResult> {
        self.environment.enter_scope();
        for stmt in statements {
            match self.interpret_statement(stmt) {
                InterpreterResult::Ok(()) => {}
                signal => {
                    self.environment.exit_scope();
                    return Some(signal);
                }
            }
        }
        self.environment.exit_scope();
        None
    }

    fn interpret_statement(&mut self, statement: &Statement) -> InterpreterResult {
        match &statement.kind {
            StatementKind::VariableDeclaration {
                name,
                var_type,
                initializer,
            } => {
                let value = match self.interpret_expression(initializer) {
                    Ok(v) => v,
                    Err(e) => return InterpreterResult::Err(e),
                };

                if matches!(var_type, frut_lib::ast::TypeExpr::Inferred) {
                    self.environment.define_variable(name.clone(), value);
                    return InterpreterResult::Ok(());
                }

                let expected_type = frut_lib::types::type_from_expr(var_type);
                let array_of_interface = matches!(
                    var_type,
                    frut_lib::ast::TypeExpr::Array { element_type, .. }
                        if matches!(&**element_type, frut_lib::ast::TypeExpr::Named(n) if self.environment.is_interface(n))
                );
                let type_ok = if array_of_interface {
                    true
                } else if matches!(&expected_type, Type::Interface { .. }) {
                    true
                } else if let Type::Struct { name, .. } = &expected_type {
                    if let Value::Enum { type_name, .. } = &value {
                        self.environment.get_enum_schema(name.as_str()).is_some()
                            && self.environment.get_enum_schema(type_name).is_some()
                            && name.as_str() == type_name.as_str()
                    } else if let Value::Struct { type_name, .. } = &value {
                        name.as_str() == type_name.as_str()
                    } else {
                        self.environment.is_interface(name)
                    }
                } else if expected_type == Type::Any {
                     true
                } else if value.get_type() == expected_type {
                    true
                } else if let Value::Enum { type_name, .. } = &value {
                    let expected_name = match &expected_type {
                        Type::Enum { name, .. } => name.as_str(),
                        _ => "",
                    };
                    !expected_name.is_empty()
                        && self.environment.get_enum_schema(type_name).is_some()
                        && self.environment.get_enum_schema(expected_name).is_some()
                        && expected_name == type_name.as_str()
                } else if let (
                    Value::Array {
                        element_type,
                        elements,
                    },
                    Type::Array {
                        element_type: expected_el,
                        len: expected_len,
                    },
                ) = (&value, &expected_type)
                {
                    let empty_ok = elements.is_empty()
                        && *element_type == Type::Any
                        && *expected_len == 0
                        && **expected_el != Type::Any;
                    let element_ok = if let Type::Struct { name, .. } = &**expected_el {
                        self.environment.is_interface(name)
                            || (self.environment.get_enum_schema(name).is_some()
                                && matches!(element_type, Type::Enum { name: en, .. } if en == name))
                    } else {
                        **expected_el == *element_type
                    };
                    empty_ok || element_ok
                } else {
                    false
                };

                if !type_ok {
                    return InterpreterResult::Err(self.create_error(
                        frut_lib::ErrorType::TypeMismatch {
                            expected: expected_type.to_string(),
                            found: value.get_type().to_string(),
                        },
                        "Type mismatch in variable declaration".to_string(),
                        &initializer.pos,
                    ));
                }

                self.environment.define_variable(name.clone(), value);
                InterpreterResult::Ok(())
            }
            StatementKind::Assignment { target, value } => {
                fn extract_path(expr: &Expression) -> Option<(String, Vec<String>)> {
                    match &expr.kind {
                        ExpressionKind::Variable(name) => Some((name.clone(), vec![])),
                        ExpressionKind::MemberAccess { object, member } => {
                            let (root, mut path) = extract_path(object)?;
                            path.push(member.clone());
                            Some((root, path))
                        }
                        _ => None,
                    }
                }

                fn set_nested_field(
                    mut v: Value,
                    path: &[String],
                    new_val: Value,
                ) -> Result<Value, String> {
                    if path.is_empty() {
                        return Ok(new_val);
                    }
                    match &mut v {
                        Value::Struct { fields, .. } => {
                            let key = &path[0];
                            let existing = fields
                                .remove(key)
                                .ok_or_else(|| format!("Struct has no field '{key}'"))?;
                            let updated = set_nested_field(existing, &path[1..], new_val)?;
                            fields.insert(key.clone(), updated);
                            Ok(v)
                        }
                        _ => Err("Member assignment target is not a struct".to_string()),
                    }
                }

                let new_value = match self.interpret_expression(value) {
                    Ok(v) => v,
                    Err(e) => return InterpreterResult::Err(e),
                };

                match &target.kind {
                    ExpressionKind::Variable(name) => {
                        if let Err(e) = self.environment.set_variable(name, new_value) {
                            return InterpreterResult::Err(self.create_error(
                                frut_lib::ErrorType::RuntimeError,
                                e,
                                &statement.pos,
                            ));
                        }
                        InterpreterResult::Ok(())
                    }
                    ExpressionKind::MemberAccess { .. } => {
                        let (root, path) = match extract_path(target) {
                            Some(p) => p,
                            None => {
                                return InterpreterResult::Err(self.create_error(
                                    frut_lib::ErrorType::RuntimeError,
                                    "Invalid assignment target".to_string(),
                                    &statement.pos,
                                ));
                            }
                        };
                        let current = match self.environment.get_variable(&root) {
                            Some(v) => v.clone(),
                            None => {
                                return InterpreterResult::Err(self.create_error(
                                    frut_lib::ErrorType::RuntimeError,
                                    format!("Variable '{root}' not found"),
                                    &statement.pos,
                                ));
                            }
                        };
                        match set_nested_field(current, &path, new_value) {
                            Ok(updated_root) => {
                                if let Err(e) = self.environment.set_variable(&root, updated_root) {
                                    return InterpreterResult::Err(self.create_error(
                                        frut_lib::ErrorType::RuntimeError,
                                        e,
                                        &statement.pos,
                                    ));
                                }
                                InterpreterResult::Ok(())
                            }
                            Err(msg) => InterpreterResult::Err(self.create_error(
                                frut_lib::ErrorType::RuntimeError,
                                msg,
                                &statement.pos,
                            )),
                        }
                    }
                    ExpressionKind::Index { object, index } => {
                        let root = match &object.kind {
                            ExpressionKind::Variable(name) => name.clone(),
                            _ => {
                                return InterpreterResult::Err(self.create_error(
                                    frut_lib::ErrorType::RuntimeError,
                                    "Invalid array assignment target".to_string(),
                                    &statement.pos,
                                ));
                            }
                        };
                        let current = match self.environment.get_variable(&root) {
                            Some(v) => v.clone(),
                            None => {
                                return InterpreterResult::Err(self.create_error(
                                    frut_lib::ErrorType::RuntimeError,
                                    format!("Variable '{root}' not found"),
                                    &statement.pos,
                                ));
                            }
                        };
                        let idx_value = match self.interpret_expression(index) {
                            Ok(Value::Int(i)) => i,
                            Ok(_) => {
                                return InterpreterResult::Err(self.create_error(
                                    frut_lib::ErrorType::TypeError,
                                    "Array index must be an integer".to_string(),
                                    &index.pos,
                                ));
                            }
                            Err(e) => return InterpreterResult::Err(e),
                        };
                        let updated = match current {
                            Value::Array {
                                element_type,
                                mut elements,
                            } => {
                                if idx_value < 0 || idx_value as usize >= elements.len() {
                                    return InterpreterResult::Err(self.create_error(
                                        frut_lib::ErrorType::IndexOutOfBounds,
                                        format!(
                                            "Index {} out of bounds for array of length {}",
                                            idx_value,
                                            elements.len()
                                        ),
                                        &statement.pos,
                                    ));
                                }
                                elements[idx_value as usize] = new_value.clone();
                                Value::Array {
                                    element_type,
                                    elements,
                                }
                            }
                            _ => {
                                return InterpreterResult::Err(self.create_error(
                                    frut_lib::ErrorType::TypeError,
                                    "Cannot index non-array value".to_string(),
                                    &statement.pos,
                                ));
                            }
                        };
                        if let Err(e) = self.environment.set_variable(&root, updated) {
                            return InterpreterResult::Err(self.create_error(
                                frut_lib::ErrorType::RuntimeError,
                                e,
                                &statement.pos,
                            ));
                        }
                        InterpreterResult::Ok(())
                    }
                    _ => InterpreterResult::Err(self.create_error(
                        frut_lib::ErrorType::RuntimeError,
                        "Invalid assignment target".to_string(),
                        &statement.pos,
                    )),
                }
            }
            StatementKind::IfStatement {
                condition,
                then_branch,
                elif_branches,
                else_branch,
            } => {
                let condition_value = match self.interpret_expression(condition) {
                    Ok(v) => v,
                    Err(e) => return InterpreterResult::Err(e),
                };

                match condition_value {
                    Value::Bool(true) => {
                        if let Some(signal) = self.interpret_scoped_block(then_branch) {
                            return signal;
                        }
                    }
                    Value::Bool(false) => {
                        let mut executed = false;
                        for (elif_condition, elif_branch) in elif_branches {
                            let elif_condition_value =
                                match self.interpret_expression(elif_condition) {
                                    Ok(v) => v,
                                    Err(e) => return InterpreterResult::Err(e),
                                };
                            if let Value::Bool(true) = elif_condition_value {
                                if let Some(signal) = self.interpret_scoped_block(elif_branch) {
                                    return signal;
                                }
                                executed = true;
                                break;
                            }
                        }

                        if !executed {
                            if let Some(else_branch) = else_branch {
                                if let Some(signal) = self.interpret_scoped_block(else_branch) {
                                    return signal;
                                }
                            }
                        }
                    }
                    _ => {
                        return InterpreterResult::Err(self.create_error(
                            frut_lib::ErrorType::TypeError,
                            "If condition must be a boolean".to_string(),
                            &condition.pos,
                        ));
                    }
                }
                InterpreterResult::Ok(())
            }
            StatementKind::MatchStatement { scrutinee, arms } => {
                let scrutinee_value = match self.interpret_expression(scrutinee) {
                    Ok(v) => v,
                    Err(e) => return InterpreterResult::Err(e),
                };

                for arm in arms {
                    let bindings = match self.match_pattern(&arm.pattern, &scrutinee_value) {
                        Ok(Some(b)) => b,
                        Ok(None) => continue,
                        Err(e) => return InterpreterResult::Err(e),
                    };

                    self.environment.enter_scope();
                    for (name, value) in bindings {
                        self.environment.define_variable(name, value);
                    }
                    for stmt in &arm.body {
                        match self.interpret_statement(stmt) {
                            InterpreterResult::Return(v) => {
                                self.environment.exit_scope();
                                return InterpreterResult::Return(v);
                            }
                            InterpreterResult::Break => {
                                self.environment.exit_scope();
                                return InterpreterResult::Break;
                            }
                            InterpreterResult::Err(e) => {
                                self.environment.exit_scope();
                                return InterpreterResult::Err(e);
                            }
                            _ => {}
                        }
                    }
                    self.environment.exit_scope();
                    return InterpreterResult::Ok(());
                }

                InterpreterResult::Err(self.create_error(
                    frut_lib::ErrorType::RuntimeError,
                    "no match arm matched value".to_string(),
                    &statement.pos,
                ))
            }
            StatementKind::WhileStatement { condition, body } => {
                while let Ok(Value::Bool(true)) = self.interpret_expression(condition) {
                    self.environment.enter_scope();
                    let mut brk = false;
                    for stmt in body {
                        match self.interpret_statement(stmt) {
                            InterpreterResult::Return(v) => {
                                self.environment.exit_scope();
                                return InterpreterResult::Return(v);
                            }
                            InterpreterResult::Break => {
                                brk = true;
                                break;
                            }
                            InterpreterResult::Err(e) => return InterpreterResult::Err(e),
                            _ => {}
                        }
                    }
                    self.environment.exit_scope();
                    if brk {
                        break;
                    }
                }
                InterpreterResult::Ok(())
            }
            StatementKind::Break => InterpreterResult::Break,
            StatementKind::Block(statements) => match self.interpret_scoped_block(statements) {
                Some(signal) => signal,
                None => InterpreterResult::Ok(()),
            },
            StatementKind::FunctionDeclaration {
                name,
                params,
                return_type,
                body,
                ..
            } => {
                let module = self.environment.get_current_module().to_string();
                let func = Value::Function {
                    name: name.clone(),
                    module,
                    params: params.clone(),
                    return_type: self.resolve_type_expr(return_type),
                    body: alloc_to_arc(body),
                    bound_self: None,
                };
                self.environment.define_function(name.clone(), func);
                InterpreterResult::Ok(())
            }
            StatementKind::Return { value } => match value {
                Some(expr) => match self.interpret_expression(expr) {
                    Ok(v) => InterpreterResult::Return(v),
                    Err(e) => InterpreterResult::Err(e),
                },
                None => InterpreterResult::Return(Value::Void),
            },
            StatementKind::ExpressionStatement(expr) => {
                if let Err(e) = self.interpret_expression(expr) {
                    return InterpreterResult::Err(e);
                }
                InterpreterResult::Ok(())
            }
            StatementKind::TypeDeclaration {
                name,
                type_params: _,
                type_param_bounds: _,
                fields,
            } => {
                let schema: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();
                self.environment.define_schema(name.clone(), schema);
                InterpreterResult::Ok(())
            }
            StatementKind::EnumDeclaration {
                name,
                type_params,
                type_param_bounds: _,
                variants,
            } => {
                let enum_schema: Vec<frut_lib::value::EnumVariantSchema> = variants
                    .iter()
                    .map(|v| frut_lib::value::EnumVariantSchema {
                        name: v.name.clone(),
                        payload_types: v.payload_types.iter().map(|t| {
                            if matches!(t, frut_lib::ast::TypeExpr::Named(n) if type_params.iter().any(|p| p == n)) {
                                frut_lib::types::Type::Any
                            } else {
                                frut_lib::types::type_from_expr(t)
                            }
                        }).collect(),
                    })
                    .collect();
                self.environment
                    .define_enum_schema(name.clone(), enum_schema);
                InterpreterResult::Ok(())
            }
            StatementKind::InterfaceDeclaration { name, .. } => {
                self.environment.define_interface(name.clone());
                InterpreterResult::Ok(())
            }
            StatementKind::ExtDeclaration {
                type_name, methods, ..
            } => {
                let module = self.environment.get_current_module().to_string();
                for method in methods {
                    match &method.kind {
                        StatementKind::FunctionDeclaration {
                            name,
                            params,
                            return_type,
                            body,
                            ..
                        } => {
                            let func = Value::Function {
                                name: format!("{type_name}__{name}"),
                                module: module.clone(),
                                params: params.clone(),
                                return_type: self.resolve_type_expr(return_type),
                                body: alloc_to_arc(body),
                                bound_self: None,
                            };
                            self.environment
                                .define_function(format!("{type_name}__{name}"), func);
                        }
                        StatementKind::ForeignFunctionDeclaration { name, .. } => {
                            let native = self.environment.get_native(name).cloned();
                            match native {
                                Some(value) => {
                                    let namespaced = format!("{type_name}__{name}");
                                    self.environment.define_function(namespaced, value);
                                }
                                None => {
                                    return InterpreterResult::Err(self.create_error(
                                        frut_lib::ErrorType::UndefinedVariable(name.clone()),
                                        format!("Native function '{name}' is not registered"),
                                        &method.pos,
                                    ));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                InterpreterResult::Ok(())
            }
            StatementKind::ImportStatement(import_stmt) => {
                match self.process_import(
                    &import_stmt.library_path,
                    &import_stmt.item,
                    &statement.pos,
                ) {
                    Ok(()) => InterpreterResult::Ok(()),
                    Err(e) => InterpreterResult::Err(e),
                }
            }
            StatementKind::ForeignFunctionDeclaration { name, .. } => {
                let native = self.environment.get_native(name).cloned();
                match native {
                    Some(value) => {
                        self.environment.define_function(name.clone(), value);
                        InterpreterResult::Ok(())
                    }
                    None => InterpreterResult::Err(self.create_error(
                        frut_lib::ErrorType::UndefinedVariable(name.clone()),
                        format!("Native function '{name}' is not registered"),
                        &statement.pos,
                    )),
                }
            }
        }
    }

    /// Process an import statement: resolve it against the module tree and bind
    /// aliases into the current module
    fn process_import(
        &mut self,
        library_path: &str,
        item: &frut_lib::ast::ImportItem,
        pos: &frut_lib::Position,
    ) -> Result<(), frut_lib::ErrorReport> {
        let mut resolver = ImportResolver::new(&self.module);
        for loaded in &self.loaded_files {
            resolver.mark_loaded(loaded.clone());
        }
        let resolved = resolver.resolve(library_path, item, pos)?;

        let mut to_execute: Vec<String> = Vec::new();
        for import in &resolved {
            if let Some(module) = import_module_name(import) {
                if !self.is_file_loaded(&module) && !to_execute.contains(&module) {
                    to_execute.push(module);
                }
            }
        }

        for module in to_execute {
            self.execute_file_if_needed(&module)?;
        }

        for import in resolved {
            self.bind_imported(&import)?;
        }
        Ok(())
    }

    /// Bind a resolved import into the current module as an alias
    fn bind_imported(&mut self, import: &ResolvedImport) -> Result<(), frut_lib::ErrorReport> {
        let current_module = self.environment.get_current_module().to_string();
        match import {
            ResolvedImport::Function {
                name,
                params,
                return_type,
                module,
                source_file,
                pos,
                ..
            } => {
                let domain = module.clone();
                let file_domain = {
                    let path = module.split('.').collect::<Vec<_>>();
                    let mut p = path[..path.len().saturating_sub(1)].to_vec();
                    p.push(source_file);
                    p.join(".")
                };
                let symbol = self
                    .environment
                    .get_function_from_module(&file_domain, name)
                    .cloned();
                match symbol {
                    Some(Value::Function { .. }) => {
                        let canonical = format!("{file_domain}~{name}");
                        self.environment.define_function_in_module(
                            &current_module,
                            canonical.clone(),
                            symbol.unwrap(),
                        );
                        self.environment
                            .define_alias(&current_module, name.clone(), canonical);
                        Ok(())
                    }
                    _ => {
                        let _ = params;
                        let _ = return_type;
                        Err(self.create_error(
                            frut_lib::ErrorType::UndefinedVariable(name.clone()),
                            format!("Function '{name}' not found in module '{domain}'"),
                            pos,
                        ))
                    }
                }
            }
            ResolvedImport::ForeignFunction {
                name,
                params,
                return_type,
                module,
                pos,
                ..
            } => {
                let native = self.environment.get_native_in(module, name).cloned();
                match native {
                    Some(value) => {
                        let canonical = format!("{module}~{name}");
                        self.environment.define_function_in_module(
                            &current_module,
                            canonical.clone(),
                            value,
                        );
                        self.environment
                            .define_alias(&current_module, name.clone(), canonical);
                        Ok(())
                    }
                    None => {
                        let _ = params;
                        let _ = return_type;
                        Err(self.create_error(
                            frut_lib::ErrorType::UndefinedVariable(name.clone()),
                            format!(
                                "Native function '{name}' from '{module}' is not registered"
                            ),
                            pos,
                        ))
                    }
                }
            }
            ResolvedImport::Type {
                name,
                module,
                variants,
                type_params,
                methods,
                interface_methods,
                ..
            } => {
                let canonical = format!("{module}~{name}");

                if !interface_methods.is_empty() {
                    self.environment.define_interface(name.clone());
                    self.environment
                        .define_alias(&current_module, name.clone(), canonical);
                    return Ok(());
                }

                if !variants.is_empty() {
                    let enum_schema: Vec<frut_lib::value::EnumVariantSchema> = variants
                        .iter()
                        .map(|v| frut_lib::value::EnumVariantSchema {
                            name: v.name.clone(),
                            payload_types: v.payload_types.iter().map(|t| {
                                if matches!(t, frut_lib::ast::TypeExpr::Named(n) if type_params.iter().any(|p| p == n)) {
                                    frut_lib::types::Type::Any
                                } else {
                                    frut_lib::types::type_from_expr(t)
                                }
                            }).collect(),
                        })
                        .collect();
                    self.environment
                        .define_enum_schema(canonical.clone(), enum_schema);
                    self.environment
                        .define_alias(&current_module, name.clone(), canonical);

                    for (method_name, _params, _return_type) in methods {
                        let source_fn = format!("{name}__{method_name}");
                        let symbol = self
                            .environment
                            .get_function_from_module(module, &source_fn)
                            .cloned();
                        if let Some(symbol) = symbol {
                            let method_canonical = format!("{module}~{method_name}");
                            self.environment.define_function_in_module(
                                &current_module,
                                method_canonical.clone(),
                                symbol,
                            );
                            self.environment.define_alias(
                                &current_module,
                                source_fn.clone(),
                                method_canonical,
                            );
                        }
                    }
                    return Ok(());
                }

                let schema = self
                    .environment
                    .get_schema(name)
                    .cloned()
                    .unwrap_or_default();
                self.environment.define_schema(canonical.clone(), schema);
                self.environment
                    .define_alias(&current_module, name.clone(), canonical);

                for (method_name, _params, _return_type) in methods {
                    let source_fn = format!("{name}__{method_name}");
                    let symbol = self
                        .environment
                        .get_function_from_module(module, &source_fn)
                        .cloned();
                    if let Some(symbol) = symbol {
                        let method_canonical = format!("{module}~{method_name}");
                        self.environment.define_function_in_module(
                            &current_module,
                            method_canonical.clone(),
                            symbol,
                        );
                        self.environment.define_alias(
                            &current_module,
                            source_fn.clone(),
                            method_canonical,
                        );
                    }
                }
                Ok(())
            }
        }
    }

    /// Try to match a pattern against a value
    fn match_pattern(
        &self,
        pattern: &frut_lib::ast::Pattern,
        value: &Value,
    ) -> Result<Option<Vec<(String, Value)>>, frut_lib::ErrorReport> {
        use frut_lib::ast::Pattern as P;

        match pattern {
            P::Wildcard => Ok(Some(Vec::new())),
            P::Literal(lit) => {
                let matched = match (lit, value) {
                    (frut_lib::ast::PatternLiteral::Int(n), Value::Int(v)) => n == v,
                    (frut_lib::ast::PatternLiteral::Double(n), Value::Double(v)) => n == v,
                    (frut_lib::ast::PatternLiteral::Bool(b), Value::Bool(v)) => b == v,
                    (frut_lib::ast::PatternLiteral::String(s), Value::String(v)) => s == v,
                    _ => false,
                };
                Ok(if matched { Some(Vec::new()) } else { None })
            }
            P::Binding(_) => Err(self.create_error(
                frut_lib::ErrorType::RuntimeError,
                "binding is only allowed inside variant arguments".to_string(),
                &frut_lib::Position::new(String::new(), 0, 0, 0, 0),
            )),
            P::EnumVariant { variant, args, .. } => {
                let (actual_variant, payload) = match value {
                    Value::Enum {
                        variant, payload, ..
                    } => (variant, payload),
                    other => {
                        return Err(self.create_error(
                            frut_lib::ErrorType::TypeError,
                            format!("cannot match enum pattern against {}", other.get_type()),
                            &frut_lib::Position::new(String::new(), 0, 0, 0, 0),
                        ));
                    }
                };
                if actual_variant != variant {
                    return Ok(None);
                }
                let mut bindings = Vec::new();
                for (arg, payload_value) in args.iter().zip(payload.iter()) {
                    match arg {
                        P::Wildcard => {}
                        P::Binding(name) => bindings.push((name.clone(), payload_value.clone())),
                        P::Literal(lit) => {
                            let matched = match lit {
                                frut_lib::ast::PatternLiteral::Int(n) => {
                                    matches!(payload_value, Value::Int(v) if v == n)
                                }
                                frut_lib::ast::PatternLiteral::Double(n) => {
                                    matches!(payload_value, Value::Double(v) if v == n)
                                }
                                frut_lib::ast::PatternLiteral::Bool(b) => {
                                    matches!(payload_value, Value::Bool(v) if v == b)
                                }
                                frut_lib::ast::PatternLiteral::String(s) => {
                                    matches!(payload_value, Value::String(v) if v == s)
                                }
                            };
                            if !matched {
                                return Ok(None);
                            }
                        }
                        P::EnumVariant { .. } | P::Or(_) => {
                            return Err(self.create_error(
                                frut_lib::ErrorType::RuntimeError,
                                "nested enum patterns are not supported yet".to_string(),
                                &frut_lib::Position::new(String::new(), 0, 0, 0, 0),
                            ));
                        }
                    }
                }
                Ok(Some(bindings))
            }
            P::Or(alts) => {
                for alt in alts {
                    if let Some(bindings) = self.match_pattern(alt, value)? {
                        return Ok(Some(bindings));
                    }
                }
                Ok(None)
            }
        }
    }

    fn interpret_expression(&mut self, expr: &Expression) -> Result<Value, frut_lib::ErrorReport> {
        match &expr.kind {
            ExpressionKind::StringLiteral(s) => Ok(Value::from_string(s.clone())),
            ExpressionKind::IntLiteral(n) => Ok(Value::from_int(*n)),
            ExpressionKind::DoubleLiteral(n) => Ok(Value::from_double(*n)),
            ExpressionKind::BoolLiteral(b) => Ok(Value::from_bool(*b)),
            ExpressionKind::Variable(name) => {
                if let Some(value) = self.lookup_symbol(name) {
                    Ok(value.clone())
                } else {
                    Err(self.create_error(
                        frut_lib::ErrorType::UndefinedVariable(name.clone()),
                        format!("Undefined variable: {name}"),
                        &expr.pos,
                    ))
                }
            }
            ExpressionKind::Unary { operator, operand } => {
                let operand_value = self.interpret_expression(operand)?;
                match operand_value.unary_op(*operator) {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        Err(self.create_error(frut_lib::ErrorType::RuntimeError, e, &expr.pos))
                    }
                }
            }
            ExpressionKind::Binary {
                left,
                operator,
                right,
            } => {
                let left_value = self.interpret_expression(left)?;
                let right_value = self.interpret_expression(right)?;
                match left_value.binary_op(*operator, &right_value) {
                    Ok(v) => Ok(v),
                    Err(e) => {
                        Err(self.create_error(frut_lib::ErrorType::RuntimeError, e, &expr.pos))
                    }
                }
            }
            ExpressionKind::FunctionCall {
                callee, arguments, ..
            } => {
                match &callee.kind {
                    ExpressionKind::Variable(name) => {
                        self.call_function(name, arguments, &callee.pos)
                    }
                    ExpressionKind::MemberAccess { object, member } => {
                        // Enum constructor: `Shape.Circle(3.14)`.
                        if let ExpressionKind::Variable(enum_name) = &object.kind {
                            if let Some(enum_schema) =
                                self.environment.get_enum_schema(enum_name).cloned()
                            {
                                if let Some(variant) =
                                    enum_schema.iter().find(|v| &v.name == member)
                                {
                                    if arguments.len() != variant.payload_types.len() {
                                        return Err(self.create_error(
                                            frut_lib::ErrorType::TypeError,
                                            format!(
                                                "Variant '{}' of enum '{}' expects {} payload argument(s), but got {}",
                                                variant.name,
                                                enum_name,
                                                variant.payload_types.len(),
                                                arguments.len()
                                            ),
                                            &callee.pos,
                                        ));
                                    }
                                    let mut payload = Vec::with_capacity(arguments.len());
                                    for arg_expr in arguments {
                                        let v = self.interpret_expression(arg_expr)?;
                                        payload.push(v);
                                    }
                                    return Ok(Value::Enum {
                                        type_name: enum_name.clone(),
                                        variant: variant.name.clone(),
                                        payload,
                                    });
                                }
                            }
                        }
                        if let ExpressionKind::Variable(struct_name) = &object.kind {
                            if self.environment.get_schema(struct_name).is_some() {
                                let namespaced = format!("{struct_name}__{member}");
                                return self.call_function(&namespaced, arguments, &callee.pos);
                            }
                        }
                        let try_obj_value = self.interpret_expression(object);
                        match try_obj_value {
                            Ok(obj_value) => {
                                let receiver_type = match &obj_value {
                                    Value::Struct { type_name, .. }
                                    | Value::Enum { type_name, .. } => {
                                        let namespaced = format!("{type_name}__{member}");
                                        match self.lookup_symbol(&namespaced) {
                                            Some(
                                                Value::Function { .. }
                                                | Value::NativeFunction { .. },
                                            ) => Some(type_name.clone()),
                                            _ => None,
                                        }
                                    }
                                    _ => None,
                                };
                                if let Some(type_name) = receiver_type {
                                    let mut all_args = Vec::with_capacity(arguments.len() + 1);
                                    all_args.push(obj_value);
                                    all_args.extend(self.eval_args(arguments)?);
                                    let namespaced = format!("{type_name}__{member}");
                                    let target = self.resolve_callable(&namespaced, &callee.pos)?;
                                    return self.call_value(&target, &all_args, &callee.pos);
                                }
                                if let Ok(target) = self.interpret_expression(callee) {
                                    if matches!(
                                        target,
                                        Value::Function { .. } | Value::NativeFunction { .. }
                                    ) {
                                        let arg_values = self.eval_args(arguments)?;
                                        return self.call_value(&target, &arg_values, &callee.pos);
                                    }
                                }
                                let arg_values = self.eval_args(arguments)?;
                                if let Some(res) = frut_lib::primitives::call(
                                    &obj_value,
                                    member.as_str(),
                                    arg_values,
                                ) {
                                    match res {
                                        Ok(v) => Ok(v),
                                        Err(e) => Err(self.create_error(
                                            frut_lib::ErrorType::RuntimeError,
                                            e,
                                            &callee.pos,
                                        )),
                                    }
                                } else {
                                    Err(self.create_error(
                                        frut_lib::ErrorType::TypeError,
                                        "Invalid method call target".to_string(),
                                        &callee.pos,
                                    ))
                                }
                            }
                            Err(_e) => Err(self.create_error(
                                frut_lib::ErrorType::TypeError,
                                "Invalid method call target".to_string(),
                                &callee.pos,
                            )),
                        }
                    }
                    _ => {
                        let callee_value = self.interpret_expression(callee)?;
                        let arg_values = self.eval_args(arguments)?;
                        self.call_value(&callee_value, &arg_values, &callee.pos)
                    }
                }
            }

            ExpressionKind::StructLiteral { type_name, fields } => {
                let mut field_values = HashMap::default();
                let schema_opt = self.environment.get_schema(type_name).cloned();
                let names_match_schema = match &schema_opt {
                    Some(schema) => fields.iter().all(|(n, _)| schema.contains(n)),
                    None => true,
                };
                if let Some(schema) = schema_opt {
                    if !names_match_schema && schema.len() == fields.len() {
                        let mut provided: Vec<(&String, &Expression)> =
                            fields.iter().map(|(n, e)| (n, e)).collect();
                        provided.sort_by(|a, b| a.0.cmp(b.0));
                        let mut decl_sorted: Vec<String> = schema.clone();
                        decl_sorted.sort();
                        for ((_, expr), decl_name) in provided.iter().zip(decl_sorted.iter()) {
                            let value = self.interpret_expression(expr)?;
                            field_values.insert(decl_name.clone(), value);
                        }
                    } else {
                        for (name, expr) in fields {
                            let value = self.interpret_expression(expr)?;
                            field_values.insert(name.clone(), value);
                        }
                    }
                } else {
                    for (name, expr) in fields {
                        let value = self.interpret_expression(expr)?;
                        field_values.insert(name.clone(), value);
                    }
                }
                Ok(Value::Struct {
                    type_name: type_name.clone(),
                    fields: field_values,
                })
            }
            ExpressionKind::MemberAccess { object, member } => {
                if let ExpressionKind::Variable(enum_name) = &object.kind {
                    if let Some(enum_schema) = self.environment.get_enum_schema(enum_name).cloned()
                    {
                        if let Some(variant) = enum_schema.iter().find(|v| &v.name == member) {
                            if variant.payload_types.is_empty() {
                                return Ok(Value::Enum {
                                    type_name: enum_name.clone(),
                                    variant: member.clone(),
                                    payload: Vec::new(),
                                });
                            }
                            return Err(self.create_error(
                                frut_lib::ErrorType::TypeError,
                                format!(
                                    "Variant '{}' of enum '{}' requires payload arguments",
                                    variant.name, enum_name
                                ),
                                &expr.pos,
                            ));
                        }
                    }
                }

                let obj_value = self.interpret_expression(object)?;
                if let Value::Enum {
                    type_name, payload, ..
                } = &obj_value
                {
                    if payload.is_empty() {
                        if let Some(enum_schema) =
                            self.environment.get_enum_schema(type_name).cloned()
                        {
                            if enum_schema.iter().any(|v| &v.name == member) {
                                return Ok(Value::Enum {
                                    type_name: type_name.clone(),
                                    variant: member.clone(),
                                    payload: Vec::new(),
                                });
                            }
                        }
                    }
                }
                match &obj_value {
                    Value::Struct {
                        type_name, fields, ..
                    } => {
                        if let Some(value) = fields.get(member) {
                            return Ok(value.clone());
                        }
                        let namespaced = format!("{type_name}__{member}");
                        self.bind_receiver(&namespaced, &obj_value, &expr.pos)
                    }
                    Value::Enum { type_name, .. } => {
                        let namespaced = format!("{type_name}__{member}");
                        if !matches!(
                            self.lookup_symbol(&namespaced),
                            Some(Value::Function { .. } | Value::NativeFunction { .. })
                        ) {
                            return Err(self.create_error(
                                frut_lib::ErrorType::TypeError,
                                format!("Enum method '{member}' cannot be used as a value"),
                                &expr.pos,
                            ));
                        }
                        self.bind_receiver(&namespaced, &obj_value, &expr.pos)
                    }
                    _ => Err(self.create_error(
                        frut_lib::ErrorType::TypeError,
                        format!(
                            "Cannot access member '{}' on a value of type {}",
                            member,
                            obj_value.get_type()
                        ),
                        &expr.pos,
                    )),
                }
            }
            ExpressionKind::ArrayLiteral(elements) => {
                let mut values = Vec::with_capacity(elements.len());
                let mut element_type = Type::Any;
                for el in elements {
                    let v = self.interpret_expression(el)?;
                    let t = v.get_type();
                    if element_type == Type::Any {
                        element_type = t;
                    }
                    values.push(v);
                }
                Ok(Value::Array {
                    element_type,
                    elements: values,
                })
            }
            ExpressionKind::Index { object, index } => {
                let obj_value = self.interpret_expression(object)?;
                let idx_value = self.interpret_expression(index)?;
                let idx = match idx_value {
                    Value::Int(i) => i,
                    _ => {
                        return Err(self.create_error(
                            frut_lib::ErrorType::TypeError,
                            "Array index must be an integer".to_string(),
                            &index.pos,
                        ));
                    }
                };
                match obj_value {
                    Value::Array { elements, .. } => {
                        if idx < 0 || idx as usize >= elements.len() {
                            return Err(self.create_error(
                                frut_lib::ErrorType::IndexOutOfBounds,
                                format!(
                                    "Index {} out of bounds for array of length {}",
                                    idx,
                                    elements.len()
                                ),
                                &expr.pos,
                            ));
                        }
                        Ok(elements[idx as usize].clone())
                    }
                    other => Err(self.create_error(
                        frut_lib::ErrorType::TypeError,
                        format!("Cannot index value of type '{}'", other.get_type()),
                        &expr.pos,
                    )),
                }
            }
            ExpressionKind::Cast { expr, target_type } => {
                let val = self.interpret_expression(expr)?;
                let target_str = target_type.to_string();
                match target_str.as_str() {
                    "int" => match val {
                        Value::Int(n) => Ok(Value::Int(n)),
                        Value::Double(n) => Ok(Value::Int(n as i64)),
                        Value::Bool(b) => Ok(Value::Int(if b { 1 } else { 0 })),
                        Value::String(s) => s.parse::<i64>().map(Value::Int).map_err(|_| {
                            self.create_error(
                                frut_lib::ErrorType::RuntimeError,
                                format!("Cannot convert string '{s}' to int"),
                                &expr.pos,
                            )
                        }),
                        _ => unreachable!("Invalid cast to int: {:?}", val),
                    },
                    "double" => match val {
                        Value::Int(n) => Ok(Value::Double(n as f64)),
                        Value::Double(n) => Ok(Value::Double(n)),
                        Value::String(s) => s.parse::<f64>().map(Value::Double).map_err(|_| {
                            self.create_error(
                                frut_lib::ErrorType::RuntimeError,
                                format!("Cannot convert string '{s}' to double"),
                                &expr.pos,
                            )
                        }),
                        _ => unreachable!("Invalid cast to double: {:?}", val),
                    },
                    "string" => match val {
                        Value::Void => Ok(Value::String("void".to_string())),
                        Value::Int(n) => Ok(Value::String(n.to_string())),
                        Value::Double(n) => Ok(Value::String(n.to_string())),
                        Value::Bool(b) => Ok(Value::String(b.to_string())),
                        Value::String(s) => Ok(Value::String(s)),
                        Value::Bytes(b) => Ok(Value::String(display_bytes(&b))),
                        Value::Function { .. } => Ok(Value::String("<function>".to_string())),
                        Value::NativeFunction { .. } => {
                            Ok(Value::String("<native function>".to_string()))
                        }
                        Value::Struct { type_name, fields } => Ok(Value::String(format!(
                            "{} {{ {} fields }}",
                            type_name,
                            fields.len()
                        ))),
                        Value::Enum {
                            type_name,
                            variant,
                            payload,
                        } => {
                            let payload_str = if payload.is_empty() {
                                String::new()
                            } else {
                                let inner = payload
                                    .iter()
                                    .map(|v| format!("{v}"))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                format!("({inner})")
                            };
                            Ok(Value::String(format!(
                                "{type_name}.{variant}{payload_str}"
                            )))
                        }
                        Value::Tuple(elements) => {
                            let inner = elements
                                .iter()
                                .map(|v| format!("{v}"))
                                .collect::<Vec<_>>()
                                .join(", ");
                            Ok(Value::String(format!("({inner})")))
                        }
                        Value::Array { elements, .. } => {
                            let inner = elements
                                .iter()
                                .map(|v| format!("{v}"))
                                .collect::<Vec<_>>()
                                .join(", ");
                            Ok(Value::String(format!("[{inner}]")))
                        }
                    },
                    "bool" => match val {
                        Value::Void => Ok(Value::Bool(false)),
                        Value::Int(n) => Ok(Value::Bool(n != 0)),
                        Value::Double(n) => Ok(Value::Bool(n != 0.0)),
                        Value::Bool(b) => Ok(Value::Bool(b)),
                        Value::String(s) => Ok(Value::Bool(!s.is_empty())),
                        Value::Bytes(b) => Ok(Value::Bool(!b.is_empty())),
                        Value::Function { .. } | Value::NativeFunction { .. } => {
                            Ok(Value::Bool(true))
                        }
                        Value::Struct { .. } => Ok(Value::Bool(true)),
                        Value::Enum { .. } => Ok(Value::Bool(true)),
                        Value::Tuple(elements) => Ok(Value::Bool(!elements.is_empty())),
                        Value::Array { elements, .. } => Ok(Value::Bool(!elements.is_empty())),
                    },
                    _ => Err(self.create_error(
                        frut_lib::ErrorType::TypeError,
                        format!("Unknown target type '{target_type}' for cast"),
                        &expr.pos,
                    )),
                }
            }
        }
    }

    /// Look up a symbol in the current module, then fall back to the global
    /// natives layer. Imported aliases resolve to their canonical names
    fn lookup_symbol(&self, name: &str) -> Option<&Value> {
        let current_module = self.environment.get_current_module().to_string();
        if let Some(canonical) = self.environment.get_alias(&current_module, name) {
            if let Some(value) = self.environment.get_function(canonical) {
                return Some(value);
            }
        }
        self.environment.get_variable(name)
    }

    /// Produce a callable for the ext method `name` (already namespaced as
    /// `Type__method`) with `receiver` bound as `self`
    fn bind_receiver(
        &mut self,
        name: &str,
        receiver: &Value,
        pos: &frut_lib::Position,
    ) -> Result<Value, frut_lib::ErrorReport> {
        match self.lookup_symbol(name) {
            Some(Value::Function { .. }) => {
                let mut bound = self.lookup_symbol(name).cloned().unwrap();
                if let Value::Function { bound_self, .. } = &mut bound {
                    *bound_self = Some(Box::new(receiver.clone()));
                }
                Ok(bound)
            }
            _ => {
                let short = name.rsplit("__").next().unwrap_or(name);
                Err(self.create_error(
                    frut_lib::ErrorType::TypeError,
                    format!(
                        "No method named '{}' on a value of type {}",
                        short,
                        receiver.get_type()
                    ),
                    pos,
                ))
            }
        }
    }

    /// Resolve a declared type annotation to a runtime [`Type`], for values
    /// that carry their own signature (functions)
    fn resolve_type_expr(&self, expr: &frut_lib::ast::TypeExpr) -> Type {
        frut_lib::types::type_from_expr(expr)
    }

    /// Evaluate an argument list.
    fn eval_args(&mut self, args: &[Expression]) -> Result<Vec<Value>, frut_lib::ErrorReport> {
        let mut values = Vec::with_capacity(args.len());
        for arg_expr in args {
            values.push(self.interpret_expression(arg_expr)?);
        }
        Ok(values)
    }

    /// Call a function *value*: a user function (optionally a bound method) or
    /// a native
    fn call_value(
        &mut self,
        callee: &Value,
        args: &[Value],
        pos: &frut_lib::Position,
    ) -> Result<Value, frut_lib::ErrorReport> {
        if self.recursion_depth >= MAX_RECURSION_DEPTH {
            return Err(self.create_error(
                frut_lib::ErrorType::RuntimeError,
                "Stack overflow".to_string(),
                pos,
            ));
        }
        self.recursion_depth += 1;
        let result = self.call_value_inner(callee, args, pos);
        self.recursion_depth -= 1;
        result
    }

    fn call_value_inner(
        &mut self,
        callee: &Value,
        args: &[Value],
        pos: &frut_lib::Position,
    ) -> Result<Value, frut_lib::ErrorReport> {
        match callee {
            Value::NativeFunction { arity, func, .. } => {
                if let Some(expected_arity) = arity {
                    if *expected_arity != args.len() {
                        return Err(self.create_error(
                            frut_lib::ErrorType::TypeError,
                            format!(
                                "Expected {} arguments, but got {}",
                                expected_arity,
                                args.len()
                            ),
                            pos,
                        ));
                    }
                }
                match func.call(args.to_vec()) {
                    Ok(result) => Ok(result),
                    Err(e) => Err(self.create_error(frut_lib::ErrorType::RuntimeError, e, pos)),
                }
            }
            Value::Function {
                name,
                params,
                body,
                module,
                bound_self,
                ..
            } => {
                let visible_arity = params.len() - usize::from(bound_self.is_some());
                if args.len() > visible_arity {
                    return Err(self.create_error(
                        frut_lib::ErrorType::TypeError,
                        format!(
                            "Expected {} arguments, but got {}",
                            visible_arity,
                            args.len()
                        ),
                        pos,
                    ));
                }

                let mut arg_values: Vec<Value> = Vec::with_capacity(args.len() + 1);
                if let Some(receiver) = bound_self {
                    arg_values.push((**receiver).clone());
                }
                arg_values.extend(args.iter().cloned());

                self.current_function.push(name.clone());

                let prev_module = self.environment.get_current_module().to_string();
                self.environment.set_current_module(module.clone());

                let result = self.execute_function_body(params, body, &arg_values);

                self.environment.set_current_module(prev_module);
                self.current_function.pop();
                result
            }
            other => Err(self.create_error(
                frut_lib::ErrorType::TypeError,
                format!("Value of type {} is not a function", other.get_type()),
                pos,
            )),
        }
    }

    /// Resolve a name to a callable value
    fn resolve_callable(
        &mut self,
        name: &str,
        pos: &frut_lib::Position,
    ) -> Result<Value, frut_lib::ErrorReport> {
        match self.lookup_symbol(name) {
            Some(v @ (Value::Function { .. } | Value::NativeFunction { .. })) => Ok(v.clone()),
            _ => Err(self.create_error(
                frut_lib::ErrorType::TypeError,
                format!("{name} is not a function"),
                pos,
            )),
        }
    }

    /// Resolve a name to a callable value and invoke it
    fn call_function(
        &mut self,
        name: &str,
        args: &[Expression],
        pos: &frut_lib::Position,
    ) -> Result<Value, frut_lib::ErrorReport> {
        let callee = self.resolve_callable(name, pos)?;
        let arg_values = self.eval_args(args)?;
        self.call_value(&callee, &arg_values, pos)
    }

    fn execute_function_body(
        &mut self,
        params: &[frut_lib::ast::Parameter],
        body: &[Statement],
        arg_values: &[Value],
    ) -> Result<Value, frut_lib::ErrorReport> {
        self.environment.enter_scope();
        for (i, (param, val)) in params.iter().zip(arg_values.iter()).enumerate() {
            if i == 0 && param.name == "self" {
                self.environment
                    .define_variable("self".to_string(), val.clone());
            } else {
                self.environment
                    .define_variable(param.name.clone(), val.clone());
            }
        }

        for stmt in body {
            match self.interpret_statement(stmt) {
                InterpreterResult::Return(val) => {
                    self.environment.exit_scope();
                    return Ok(val);
                }
                InterpreterResult::Err(e) => {
                    self.environment.exit_scope();
                    return Err(e);
                }
                _ => {}
            }
        }

        self.environment.exit_scope();
        Ok(Value::Void)
    }

    /// Get the runtime environment (for debugging/testing)
    pub fn get_environment(&self) -> &RuntimeEnvironment {
        &self.environment
    }

    /// Get a mutable reference to the runtime environment (for custom registrations)
    pub fn environment_mut(&mut self) -> &mut RuntimeEnvironment {
        &mut self.environment
    }
}

/// The module a resolved import belongs to (the fully-qualified file path that
/// must be executed before the symbol can be bound)
fn import_module_name(import: &ResolvedImport) -> Option<String> {
    match import {
        ResolvedImport::Function {
            module,
            source_file,
            ..
        } => {
            let mut parts: Vec<&str> = module.split('.').collect();
            parts.pop();
            parts.push(source_file);
            Some(parts.join("."))
        }
        ResolvedImport::ForeignFunction { module, .. } => Some(module.clone()),
        ResolvedImport::Type { module, .. } => Some(module.clone()),
    }
}

fn find_file_in<'a>(module: &'a Module, parts: &[&str]) -> Option<&'a frut_lib::File> {
    if parts.is_empty() {
        return None;
    }
    let (head, rest) = parts.split_at(1);
    // Try as a submodule first; fall back to a direct file
    if let Some(sub) = module.find_submodule(head[0]) {
        if let Some(file) = find_file_in(sub, rest) {
            return Some(file);
        }
    }
    if rest.is_empty() {
        module.files.iter().find(|f| f.name == head[0])
    } else {
        None
    }
}
