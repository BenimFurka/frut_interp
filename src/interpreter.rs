//! Interpreter for the Frut
//!
//! Executes parsed AST nodes and produces runtime values.

use frut_lib::ast::{Expression, ExpressionKind, Statement, StatementKind};
use frut_lib::types::Type;
use frut_lib::value::{RuntimeEnvironment, Value};
use frut_lib::HashMap;

/// Result type for interpreter operations
pub enum InterpreterResult {
    Ok(()),
    Return(Value),
    TailCall { _name: String, _args: Vec<Value> },
    Err(frut_lib::ErrorReport),
}

const MAX_RECURSION_DEPTH: u32 = 512;

/// Interpreter for the Frut
pub struct Interpreter {
    environment: RuntimeEnvironment,
    filename: String,
    source: String,
    recursion_depth: u32,
    current_function: Vec<String>,
}

impl Interpreter {
    /// Create a new semantic analyzer with built-in functions predeclared
    pub fn create_semantic_analyzer(filename: String, source: String) -> frut_lib::semantic::SemanticAnalyzer {
        let analyzer = frut_lib::semantic::SemanticAnalyzer::new(filename, source);
        analyzer
    }
    
    /// Create a new interpreter with built-in functions
    pub fn new(filename: String, source: String) -> Self {
        let env = RuntimeEnvironment::new();
        
        Self {
            environment: env,
            filename,
            source,
            recursion_depth: 0,
            current_function: Vec::new(),
        }
    }

    /// Interpret a list of statements
    pub fn interpret(&mut self, statements: &[Statement]) -> Result<(), frut_lib::ErrorReport> {
        for statement in statements {
            match self.interpret_statement(statement) {
                InterpreterResult::Ok(_) => {}
                InterpreterResult::Return(_) => {
                                let pos = statement.pos.clone();
                                return Err(self.create_error(frut_lib::ErrorType::RuntimeError, "Cannot return from top-level".to_string(), &pos));
                            }
                InterpreterResult::Err(e) => return Err(e),
                InterpreterResult::TailCall { _name, _args } => {},
            }
        }
        Ok(())
    }

    /// Interpret a single statement
    fn create_error(&self, error_type: frut_lib::ErrorType, message: String, pos: &frut_lib::Position) -> frut_lib::ErrorReport {
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

    fn interpret_statement(&mut self, statement: &Statement) -> InterpreterResult {
        match &statement.kind {
            StatementKind::VariableDeclaration { name, var_type, initializer } => {
                let value = match self.interpret_expression(initializer) {
                    Ok(v) => v,
                    Err(e) => return InterpreterResult::Err(e),
                };

                let expected_type = Type::from(var_type.as_str());
                if value.get_type() != expected_type {
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

                fn set_nested_field(mut v: Value, path: &[String], new_val: Value) -> Result<Value, String> {
                    if path.is_empty() {
                        return Ok(new_val);
                    }
                    match &mut v {
                        Value::Struct { fields, .. } => {
                            let key = &path[0];
                            let existing = fields.remove(key).ok_or_else(|| format!("Struct has no field '{}'", key))?;
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
                            return InterpreterResult::Err(self.create_error(frut_lib::ErrorType::RuntimeError, e, &statement.pos));
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
                                    format!("Variable '{}' not found", root),
                                    &statement.pos,
                                ));
                            }
                        };
                        match set_nested_field(current, &path, new_value) {
                            Ok(updated_root) => {
                                if let Err(e) = self.environment.set_variable(&root, updated_root) {
                                    return InterpreterResult::Err(self.create_error(frut_lib::ErrorType::RuntimeError, e, &statement.pos));
                                }
                                InterpreterResult::Ok(())
                            }
                            Err(msg) => InterpreterResult::Err(self.create_error(frut_lib::ErrorType::RuntimeError, msg, &statement.pos)),
                        }
                    }
                    _ => InterpreterResult::Err(self.create_error(
                        frut_lib::ErrorType::RuntimeError,
                        "Invalid assignment target".to_string(),
                        &statement.pos,
                    )),
                }
            }
            StatementKind::IfStatement { condition, then_branch, elif_branches, else_branch } => {
                let condition_value = match self.interpret_expression(condition) {
                    Ok(v) => v,
                    Err(e) => return InterpreterResult::Err(e),
                };

                match condition_value {
                    Value::Bool(true) => {
                        self.environment.enter_scope();
                        for stmt in then_branch {
                            if let InterpreterResult::Return(v) = self.interpret_statement(stmt) {
                                self.environment.exit_scope();
                                return InterpreterResult::Return(v);
                            }
                        }
                        self.environment.exit_scope();
                    }
                    Value::Bool(false) => {
                        let mut executed = false;
                        for (elif_condition, elif_branch) in elif_branches {
                            let elif_condition_value = match self.interpret_expression(elif_condition) {
                                Ok(v) => v,
                                Err(e) => return InterpreterResult::Err(e),
                            };
                            if let Value::Bool(true) = elif_condition_value {
                                self.environment.enter_scope();
                                for stmt in elif_branch {
                                    if let InterpreterResult::Return(v) = self.interpret_statement(stmt) {
                                        self.environment.exit_scope();
                                        return InterpreterResult::Return(v);
                                    }
                                }
                                self.environment.exit_scope();
                                executed = true;
                                break;
                            }
                        }

                        if !executed {
                            if let Some(else_branch) = else_branch {
                                self.environment.enter_scope();
                                for stmt in else_branch {
                                    if let InterpreterResult::Return(v) = self.interpret_statement(stmt) {
                                        self.environment.exit_scope();
                                        return InterpreterResult::Return(v);
                                    }
                                }
                                self.environment.exit_scope();
                            }
                        }
                    }
                    _ => {
                        return InterpreterResult::Err(self.create_error(frut_lib::ErrorType::TypeError, "If condition must be a boolean".to_string(), &condition.pos));
                    }
                }
                InterpreterResult::Ok(())
            }
            StatementKind::WhileStatement { condition, body } => {
                while let Ok(Value::Bool(true)) = self.interpret_expression(condition) {
                    self.environment.enter_scope();
                    for stmt in body {
                        match self.interpret_statement(stmt) {
                            InterpreterResult::Return(v) => {
                                self.environment.exit_scope();
                                return InterpreterResult::Return(v);
                            }
                            InterpreterResult::Err(e) => return InterpreterResult::Err(e),
                            _ => {}
                        }
                    }
                    self.environment.exit_scope();
                }
                InterpreterResult::Ok(())
            }
            StatementKind::Block(statements) => {
                self.environment.enter_scope();
                for stmt in statements {
                    match self.interpret_statement(stmt) {
                        InterpreterResult::Return(v) => {
                            self.environment.exit_scope();
                            return InterpreterResult::Return(v);
                        }
                        InterpreterResult::Err(e) => {
                            self.environment.exit_scope();
                            return InterpreterResult::Err(e);
                        }
                        _ => {}
                    }
                }
                self.environment.exit_scope();
                InterpreterResult::Ok(())
            }
            StatementKind::FunctionDeclaration { name, params, body, .. } => {
                let return_type = Type::Void;
                
                let func = Value::Function {
                    name: name.clone(),
                    params: params.clone(),
                    return_type,
                    body: body.clone(),
                };
                self.environment.define_function(name.clone(), func);
                InterpreterResult::Ok(())
            }
            StatementKind::Return { value } => {
                match value {
                    Some(expr) => {
                        if let Some(current_name) = self.current_function.last() {
                            if let ExpressionKind::FunctionCall { callee, arguments } = &expr.kind {
                                if let ExpressionKind::Variable(fname) = &callee.kind {
                                    if fname == current_name {
                                        let mut vals = Vec::with_capacity(arguments.len());
                                        for a in arguments {
                                            match self.interpret_expression(a) {
                                                Ok(v) => vals.push(v),
                                                Err(e) => return InterpreterResult::Err(e),
                                            }
                                        }
                                        return InterpreterResult::TailCall { _name: fname.clone(), _args: vals };
                                    }
                                }
                            }
                        }
                        return match self.interpret_expression(expr) {
                            Ok(v) => InterpreterResult::Return(v),
                            Err(e) => InterpreterResult::Err(e),
                        };
                    }
                    None => return InterpreterResult::Return(Value::Void),
                }
            }
            StatementKind::ExpressionStatement(expr) => {
                if let Err(e) = self.interpret_expression(expr) {
                    return InterpreterResult::Err(e);
                }
                InterpreterResult::Ok(())
            }
            StatementKind::Import { .. } => {
                InterpreterResult::Ok(())
            }
            StatementKind::TypeDeclaration { name, fields } => {
                let schema: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();
                self.environment.define_schema(name.clone(), schema);
                InterpreterResult::Ok(())
            }
            StatementKind::ExtDeclaration { type_name, methods } => {
                for method in methods {
                    if let StatementKind::FunctionDeclaration { name, params, body, .. } = &method.kind {
                        let return_type = Type::Void;
                        let func = Value::Function {
                            name: format!("{}__{}", type_name, name),
                            params: params.clone(),
                            return_type,
                            body: body.clone(),
                        };
                        self.environment.define_function(format!("{}__{}", type_name, name), func);
                    }
                }
                InterpreterResult::Ok(())
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
                match self.environment.get_variable(name) {
                    Some(value) => Ok(value.clone()),
                    None => Err(self.create_error(frut_lib::ErrorType::UndefinedVariable(name.clone()), format!("Undefined variable: {}", name), &expr.pos)),
                }
            }
            ExpressionKind::Unary { operator, operand } => {
                let operand_value = self.interpret_expression(operand)?;
                match operand_value.unary_op(*operator) {
                    Ok(v) => Ok(v),
                    Err(e) => Err(self.create_error(frut_lib::ErrorType::RuntimeError, e, &expr.pos)),
                }
            }
            ExpressionKind::Binary { left, operator, right } => {
                let left_value = self.interpret_expression(left)?;
                let right_value = self.interpret_expression(right)?;
                match left_value.binary_op(*operator, &right_value) {
                    Ok(v) => Ok(v),
                    Err(e) => Err(self.create_error(frut_lib::ErrorType::RuntimeError, e, &expr.pos)),
                }
            }
            ExpressionKind::FunctionCall { callee, arguments } => {
                match &callee.kind {
                    ExpressionKind::Variable(name) => {
                        self.call_function(name, arguments, &callee.pos)
                    }
                    ExpressionKind::MemberAccess { object, member } => {
                        if let ExpressionKind::Variable(struct_name) = &object.kind {
                            if self.environment.get_schema(struct_name).is_some() {
                                let namespaced = format!("{}__{}", struct_name, member);
                                return self.call_function(&namespaced, arguments, &callee.pos);
                            }
                        }
                        let try_obj_value = self.interpret_expression(object);
                        match try_obj_value {
                            Ok(Value::Struct { type_name, .. }) => {
                                let mut all_args = Vec::with_capacity(arguments.len() + 1);
                                all_args.push(*object.clone());
                                all_args.extend(arguments.iter().cloned());
                                let namespaced = format!("{}__{}", type_name, member);
                                self.call_function(&namespaced, &all_args, &callee.pos)
                            }
                            Ok(non_struct_val) => {
                                let mut arg_values = Vec::with_capacity(arguments.len());
                                for arg_expr in arguments {
                                    let v = self.interpret_expression(arg_expr)?;
                                    arg_values.push(v);
                                }
                                if let Some(res) = frut_lib::primitives::call(&non_struct_val, member.as_str(), arg_values) {
                                    match res {
                                        Ok(v) => Ok(v),
                                        Err(e) => Err(self.create_error(frut_lib::ErrorType::RuntimeError, e, &callee.pos)),
                                    }
                                } else {
                                    Err(self.create_error(frut_lib::ErrorType::TypeError, "Invalid method call target".to_string(), &callee.pos))
                                }
                            }
                            Err(_e) => {
                                Err(self.create_error(frut_lib::ErrorType::TypeError, "Invalid method call target".to_string(), &callee.pos))
                            }
                        }
                    }
                    _ => {
                        Err(self.create_error(frut_lib::ErrorType::TypeError, "Callee is not a variable".to_string(), &callee.pos))
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
                        let mut provided: Vec<(&String, &Expression)> = fields.iter().map(|(n,e)| (n,e)).collect();
                        provided.sort_by(|a,b| a.0.cmp(b.0));
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
                Ok(Value::Struct { type_name: type_name.clone(), fields: field_values })
            }
            ExpressionKind::MemberAccess { object, member } => {
                let obj_value = self.interpret_expression(object)?;
                if let Value::Struct { fields, .. } = obj_value {
                    if let Some(value) = fields.get(member) {
                        Ok(value.clone())
                    } else {
                        Err(self.create_error(
                            frut_lib::ErrorType::RuntimeError,
                            format!("Struct has no field '{}'", member),
                            &expr.pos
                        ))
                    }
                } else {
                    Err(self.create_error(
                        frut_lib::ErrorType::TypeError,
                        "Member access can only be performed on structs".to_string(),
                        &expr.pos
                    ))
                }
            }
            ExpressionKind::Cast { expr, target_type } => {
                let val = self.interpret_expression(expr)?;
                match target_type.as_str() {
                    "int" => match val {
                        Value::Int(n) => Ok(Value::Int(n)),
                        Value::Double(n) => Ok(Value::Int(n as i64)),
                        Value::Bool(b) => Ok(Value::Int(if b { 1 } else { 0 })),
                        Value::String(s) => s.parse::<i64>()
                            .map(Value::Int)
                            .map_err(|_| self.create_error(
                                frut_lib::ErrorType::RuntimeError,
                                format!("Cannot convert string '{}' to int", s),
                                &expr.pos
                            )),
                        _ => unreachable!("Invalid cast to int: {:?}", val),
                    },
                    "double" => match val {
                        Value::Int(n) => Ok(Value::Double(n as f64)),
                        Value::Double(n) => Ok(Value::Double(n)),
                        Value::String(s) => s.parse::<f64>()
                            .map(Value::Double)
                            .map_err(|_| self.create_error(
                                frut_lib::ErrorType::RuntimeError,
                                format!("Cannot convert string '{}' to double", s),
                                &expr.pos
                            )),
                        _ => unreachable!("Invalid cast to double: {:?}", val),
                    },
                    "string" => match val {
                        Value::Void => Ok(Value::String("void".to_string())),
                        Value::Int(n) => Ok(Value::String(n.to_string())),
                        Value::Double(n) => Ok(Value::String(n.to_string())),
                        Value::Bool(b) => Ok(Value::String(b.to_string())),
                        Value::String(s) => Ok(Value::String(s)),
                        Value::Function { .. } => Ok(Value::String("<function>".to_string())),
                        Value::NativeFunction { .. } => Ok(Value::String("<native function>".to_string())),
                        Value::Struct { type_name, fields } => {
                            Ok(Value::String(format!("{} {{ {} fields }}", type_name, fields.len())))
                        }
                    },
                    "bool" => match val {
                        Value::Void => Ok(Value::Bool(false)),
                        Value::Int(n) => Ok(Value::Bool(n != 0)),
                        Value::Double(n) => Ok(Value::Bool(n != 0.0)),
                        Value::Bool(b) => Ok(Value::Bool(b)),
                        Value::String(s) => Ok(Value::Bool(!s.is_empty())),
                        Value::Function { .. } | Value::NativeFunction { .. } => Ok(Value::Bool(true)),
                        Value::Struct { .. } => Ok(Value::Bool(true)),
                    },
                    _ => Err(self.create_error(
                        frut_lib::ErrorType::TypeError,
                        format!("Unknown target type '{}' for cast", target_type),
                        &expr.pos
                    )),
                }
            }
        }
    }

    fn call_function(&mut self, name: &str, args: &[Expression], pos: &frut_lib::Position) -> Result<Value, frut_lib::ErrorReport> {
        if self.recursion_depth >= MAX_RECURSION_DEPTH {
            return Err(self.create_error(frut_lib::ErrorType::RuntimeError, "Stack overflow".to_string(), pos));
        }

        self.recursion_depth += 1;

        let native_func = match self.environment.get_variable(name) {
            Some(Value::NativeFunction { arity, func, .. }) => {
                if let Some(expected_arity) = arity {
                    if *expected_arity != args.len() {
                        let err = self.create_error(
                            frut_lib::ErrorType::TypeError, 
                            format!("Expected {} arguments, but got {}", expected_arity, args.len()), 
                            pos
                        );
                        self.recursion_depth -= 1;
                        return Err(err);
                    }
                }
                Some(func.clone())
            }
            _ => None,
        };

        if let Some(func) = native_func {
            let mut arg_values = Vec::with_capacity(args.len());
            for arg_expr in args {
                let val = self.interpret_expression(arg_expr)?;
                arg_values.push(val);
            }

            match func.call(arg_values) {
                Ok(result) => {
                    self.recursion_depth -= 1;
                    Ok(result)
                }
                Err(e) => {
                    let err = self.create_error(frut_lib::ErrorType::RuntimeError, e, pos);
                    self.recursion_depth -= 1;
                    Err(err)
                }
            }
        } else if let Some(Value::Function { params, body, .. }) = self.environment.get_variable(name).cloned() {
            if args.len() > params.len() {
                let err = self.create_error(frut_lib::ErrorType::TypeError, format!("Expected {} arguments, but got {}", params.len(), args.len()), pos);
                self.recursion_depth -= 1;
                return Err(err);
            }
            
            let mut arg_values: Vec<Value> = Vec::with_capacity(args.len());
            for arg_expr in args.iter() {
                let v = self.interpret_expression(arg_expr)?;
                arg_values.push(v);
            }

            self.current_function.push(name.to_string());

            loop {
                self.environment.enter_scope();

                for (i, (param, val)) in params.iter().zip(arg_values.iter()).enumerate() {
                    if i == 0 && param.name == "self" {
                        self.environment.define_variable("self".to_string(), val.clone());
                    } else {
                        self.environment.define_variable(param.name.clone(), val.clone());
                    }
                }

                let mut did_tailcall = false;
                for stmt in &body {
                    match self.interpret_statement(stmt) {
                        InterpreterResult::Return(val) => {
                            self.environment.exit_scope();
                            self.current_function.pop();
                            self.recursion_depth -= 1;
                            return Ok(val);
                        }
                        InterpreterResult::TailCall { _name: tn, _args } => {
                            if tn == *self.current_function.last().unwrap() {
                                self.environment.exit_scope();
                                arg_values = _args;
                                did_tailcall = true;
                                break;
                            } else {
                                self.environment.exit_scope();
                                self.current_function.pop();
                                self.recursion_depth -= 1;
                                let res = self.call_function(&tn, &[], pos);
                                return res;
                            }
                        }
                        InterpreterResult::Err(e) => {
                            self.environment.exit_scope();
                            self.current_function.pop();
                            self.recursion_depth -= 1;
                            return Err(e);
                        }
                        _ => {}
                    }
                }

                if !did_tailcall {
                    self.environment.exit_scope();
                    self.current_function.pop();
                    self.recursion_depth -= 1;
                    return Ok(Value::Void);
                }
            }
        } else {
            let err = self.create_error(
                frut_lib::ErrorType::TypeError, 
                format!("{} is not a function", name), 
                pos
            );
            self.recursion_depth -= 1;
            Err(err)
        }
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
