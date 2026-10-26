//! Host implementations of native (foreign) functions for the Frut interpreter.
//!
//! `frut_lib` only provides the [`NativeRegistry`] interface; actual I/O and
//! math implementations live here, in the host crate.

use frut_lib::types::Type;
use frut_lib::value::{NativeFnWrapper, Value};
use frut_lib::NativeFnDef;
use std::cell::RefCell;

/// Convenience wrapper for declaring a native function
pub fn native<F, A, R>(
    module: &'static str,
    name: &'static str,
    return_type: Type,
    params: &[(&str, Type)],
    func: F,
) -> NativeFnDef
where
    F: Fn(A) -> Result<R, String> + Send + Sync + 'static,
    A: FromArgs,
    R: IntoValue,
{
    let param_vec: Vec<(String, Type)> = params
        .iter()
        .map(|(n, t)| (n.to_string(), t.clone()))
        .collect();
    let wrapper = NativeFnWrapper::new(move |args: Vec<Value>| {
        let a = A::from_args(&args).map_err(|msg| format!("{name}: {msg}"))?;
        let r = func(a)?;
        Ok(r.into_value())
    });
    NativeFnDef {
        name,
        module,
        params: param_vec,
        return_type,
        func: wrapper,
    }
}

/// A numeric Frut value that is either an `int` or a `double`
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Num {
    Int(i64),
    Double(f64),
}

impl Num {
    /// The value as `f64` (int is widened)
    pub fn as_f64(self) -> f64 {
        match self {
            Num::Int(n) => n as f64,
            Num::Double(d) => d,
        }
    }
}

/// Conversion from a native return value into a [`Value`]
pub trait IntoValue {
    fn into_value(self) -> Value;
}

impl IntoValue for () {
    fn into_value(self) -> Value {
        Value::Void
    }
}
impl IntoValue for i64 {
    fn into_value(self) -> Value {
        Value::Int(self)
    }
}
impl IntoValue for f64 {
    fn into_value(self) -> Value {
        Value::Double(self)
    }
}
impl IntoValue for String {
    fn into_value(self) -> Value {
        Value::String(self)
    }
}
impl IntoValue for bool {
    fn into_value(self) -> Value {
        Value::Bool(self)
    }
}

impl IntoValue for Vec<u8> {
    fn into_value(self) -> Value {
        Value::Bytes(self)
    }
}
impl IntoValue for &[u8] {
    fn into_value(self) -> Value {
        Value::Bytes(self.to_vec())
    }
}
impl IntoValue for Num {
    fn into_value(self) -> Value {
        match self {
            Num::Int(n) => Value::Int(n),
            Num::Double(d) => Value::Double(d),
        }
    }
}
impl IntoValue for Value {
    fn into_value(self) -> Value {
        self
    }
}

/// Types that can be destructured from a `Vec<Value>`.
pub trait FromArgs: Sized {
    fn from_args(args: &[Value]) -> Result<Self, String>;
}

impl FromArgs for () {
    fn from_args(args: &[Value]) -> Result<Self, String> {
        if !args.is_empty() {
            return Err(format!("expected 0 arguments, got {}", args.len()));
        }
        Ok(())
    }
}

macro_rules! impl_from_args_single {
    ($ty:ty, $variant:ident, $convert:expr, $label:expr) => {
        impl FromArgs for $ty {
            fn from_args(args: &[Value]) -> Result<Self, String> {
                if args.len() != 1 {
                    return Err(format!("expected 1 argument, got {}", args.len()));
                }
                match &args[0] {
                    Value::$variant(v) => Ok($convert(v)),
                    other => Err(format!("expected {}, got {}", $label, other.get_type())),
                }
            }
        }
    };
}
impl_from_args_single!(i64, Int, |v: &i64| *v, "int");
impl_from_args_single!(f64, Double, |v: &f64| *v, "double");
impl_from_args_single!(String, String, |v: &String| v.clone(), "string");
impl_from_args_single!(bool, Bool, |v: &bool| *v, "bool");

impl FromArgs for Vec<u8> {
    fn from_args(args: &[Value]) -> Result<Self, String> {
        if args.len() != 1 {
            return Err(format!("expected 1 argument, got {}", args.len()));
        }
        match &args[0] {
            Value::Bytes(b) => Ok(b.clone()),
            other => Err(format!("expected bytes, got {}", other.get_type())),
        }
    }
}

impl FromArgs for Num {
    fn from_args(args: &[Value]) -> Result<Self, String> {
        if args.len() != 1 {
            return Err(format!("expected 1 argument, got {}", args.len()));
        }
        match &args[0] {
            Value::Int(n) => Ok(Num::Int(*n)),
            Value::Double(d) => Ok(Num::Double(*d)),
            other => Err(format!("expected a number, got {}", other.get_type())),
        }
    }
}

impl FromArgs for Value {
    fn from_args(args: &[Value]) -> Result<Self, String> {
        if args.len() != 1 {
            return Err(format!("expected 1 argument, got {}", args.len()));
        }
        Ok(args[0].clone())
    }
}

impl<A: FromArgs, B: FromArgs> FromArgs for (A, B) {
    fn from_args(args: &[Value]) -> Result<Self, String> {
        if args.len() != 2 {
            return Err(format!("expected 2 arguments, got {}", args.len()));
        }
        Ok((A::from_args(&args[0..1])?, B::from_args(&args[1..2])?))
    }
}

impl<A: FromArgs, B: FromArgs, C: FromArgs> FromArgs for (A, B, C) {
    fn from_args(args: &[Value]) -> Result<Self, String> {
        if args.len() != 3 {
            return Err(format!("expected 3 arguments, got {}", args.len()));
        }
        Ok((
            A::from_args(&args[0..1])?,
            B::from_args(&args[1..2])?,
            C::from_args(&args[2..3])?,
        ))
    }
}

thread_local! {
    /// Per-thread vector table. `Value` is not `Send` (it may hold `Rc`), so
    /// the store lives in thread-local storage; the interpreter runs script
    /// code on a single OS thread
    static VEC_STORE: RefCell<Vec<Option<Vec<Value>>>> = const { RefCell::new(Vec::new()) };
}

/// Resolve a handle to a live vector, or `None` when invalid/freed
fn vec_with<R>(h: i64, f: impl FnOnce(&Vec<Value>) -> R) -> Option<R> {
    if h < 0 {
        return None;
    }
    VEC_STORE.with(|s| s.borrow().get(h as usize)?.as_ref().map(f))
}

fn vec_with_mut<R>(h: i64, f: impl FnOnce(&mut Vec<Value>) -> R) -> Option<R> {
    if h < 0 {
        return None;
    }
    VEC_STORE.with(|s| s.borrow_mut().get_mut(h as usize)?.as_mut().map(f))
}

/// Extract a `Value` argument as an `i64` (for indices/handles)
fn as_int(value: &Value) -> Result<i64, String> {
    match value {
        Value::Int(n) => Ok(*n),
        other => Err(format!("expected int, got {}", other.get_type())),
    }
}

/// Register all host-native implementations into the given registry
pub fn register_host_natives(registry: &mut frut_lib::NativeRegistry) {
    // -- Low-level I/O (domain: std.native.io) --------------------------------
    registry.register(native(
        "std.native.io",
        "native_write_stdout",
        Type::Void,
        &[("data", Type::String)],
        |v: Value| {
            print!("{v}");
            Ok(())
        },
    ));

    registry.register(native(
        "std.native.io",
        "native_write_stderr",
        Type::Void,
        &[("data", Type::String)],
        |v: Value| {
            eprint!("{v}");
            Ok(())
        },
    ));

    registry.register(native(
        "std.native.io",
        "native_read_stdin",
        Type::String,
        &[],
        |_: ()| {
            use std::io;
            let mut input = String::new();
            match io::stdin().read_line(&mut input) {
                Ok(_) => Ok(input.trim_end().to_string()),
                Err(e) => Err(format!("Failed to read from stdin: {e}")),
            }
        },
    ));

    // -- Test/dev bridges (domain: std.native.io) -----------------------------
    registry.register(native(
        "std.native.io",
        "native_make_bytes",
        Type::Bytes,
        &[("n", Type::Int)],
        |n: i64| Ok((0..n.max(0)).map(|i| (i % 256) as u8).collect::<Vec<u8>>()),
    ));

    // -- Math (domain: std.math) ---------------------------------------------
    registry.register(native(
        "std.native.math",
        "native_abs",
        Type::Int,
        &[("x", Type::Int)],
        |x: Num| match x {
            Num::Int(n) => Ok(Num::Int(n.abs())),
            Num::Double(d) => Ok(Num::Double(d.abs())),
        },
    ));
    registry.register(native(
        "std.native.math",
        "native_min",
        Type::Int,
        &[("a", Type::Int), ("b", Type::Int)],
        |(a, b): (Num, Num)| match (a, b) {
            (Num::Int(x), Num::Int(y)) => Ok(Num::Int(x.min(y))),
            (x, y) => Ok(Num::Double(x.as_f64().min(y.as_f64()))),
        },
    ));
    registry.register(native(
        "std.native.math",
        "native_max",
        Type::Int,
        &[("a", Type::Int), ("b", Type::Int)],
        |(a, b): (Num, Num)| match (a, b) {
            (Num::Int(x), Num::Int(y)) => Ok(Num::Int(x.max(y))),
            (x, y) => Ok(Num::Double(x.as_f64().max(y.as_f64()))),
        },
    ));
    registry.register(native(
        "std.native.math",
        "native_sqrt",
        Type::Double,
        &[("x", Type::Double)],
        |x: Num| Ok(x.as_f64().sqrt()),
    ));
    registry.register(native(
        "std.native.math",
        "native_pow",
        Type::Int,
        &[("base", Type::Int), ("exp", Type::Int)],
        |(base, exp): (i64, i64)| Ok(base.wrapping_pow(exp.max(0) as u32)),
    ));

    // -- Strings (domain: std.native.strings) ---------------------------------
    registry.register(native(
        "std.native.strings",
        "native_str_len",
        Type::Int,
        &[("s", Type::String)],
        |s: String| Ok(s.len() as i64),
    ));
    registry.register(native(
        "std.native.strings",
        "native_str_char_at",
        Type::String,
        &[("s", Type::String), ("i", Type::Int)],
        |(s, i): (String, i64)| {
            let bytes = s.as_bytes();
            if i < 0 || i as usize >= bytes.len() {
                return Err(format!("char_at: index {i} out of range"));
            }
            
            Ok(String::from_utf8_lossy(&bytes[i as usize..i as usize + 1]).into_owned())
        },
    ));
    registry.register(native(
        "std.native.strings",
        "native_str_char_code",
        Type::Int,
        &[("s", Type::String), ("i", Type::Int)],
        |(s, i): (String, i64)| {
            let bytes = s.as_bytes();
            if i < 0 || i as usize >= bytes.len() {
                return Err(format!("char_code: index {i} out of range"));
            }
            Ok(bytes[i as usize] as i64)
        },
    ));
    registry.register(native(
        "std.native.strings",
        "native_str_substring",
        Type::String,
        &[("s", Type::String), ("start", Type::Int), ("end", Type::Int)],
        |(s, start, end): (String, i64, i64)| {
            let bytes = s.as_bytes();
            let n = bytes.len() as i64;
            if start < 0 || end < start || end > n {
                return Err(format!("substring: range [{start}, {end}) out of bounds"));
            }
            Ok(String::from_utf8_lossy(&bytes[start as usize..end as usize]).into_owned())
        },
    ));
    registry.register(native(
        "std.native.strings",
        "native_str_from_code",
        Type::String,
        &[("code", Type::Int)],
        |code: i64| {
            if !(0..=255).contains(&code) {
                return Err(format!("str_from_code: code {code} is not a byte"));
            }
            Ok(String::from_utf8_lossy(&[code as u8]).into_owned())
        },
    ));
    registry.register(native(
        "std.native.strings",
        "native_str_index_of",
        Type::Int,
        &[("s", Type::String), ("sub", Type::String)],
        |(s, sub): (String, String)| {
            match s.find(&sub) {
                Some(pos) => Ok(pos as i64),
                None => Ok(-1),
            }
        },
    ));

    // -- Vectors (domain: std.native.vec) -------------------------------------
    registry.register(native(
        "std.native.vec",
        "native_vec_new",
        Type::Int,
        &[],
        |_: ()| {
            VEC_STORE.with(|s| {
                let mut store = s.borrow_mut();
                store.push(Some(Vec::new()));
                Ok((store.len() - 1) as i64)
            })
        },
    ));
    registry.register(native(
        "std.native.vec",
        "native_vec_push",
        Type::Bool,
        &[("h", Type::Int), ("v", Type::Any)],
        |(h, v): (i64, Value)| {
            vec_with_mut(h, |items| {
                items.push(v);
                true
            })
            .ok_or_else(|| format!("vec_push: invalid handle {h}"))
        },
    ));
    registry.register(native(
        "std.native.vec",
        "native_vec_get",
        Type::Any,
        &[("h", Type::Int), ("i", Type::Int)],
        |(h, i): (i64, i64)| {
            vec_with(h, |items| {
                if i < 0 || i as usize >= items.len() {
                    Err(format!("vec_get: index {i} out of range"))
                } else {
                    Ok(items[i as usize].clone())
                }
            })
            .ok_or_else(|| format!("vec_get: invalid handle {h}"))?
        },
    ));
    registry.register(native(
        "std.native.vec",
        "native_vec_set",
        Type::Bool,
        &[("h", Type::Int), ("i", Type::Int), ("v", Type::Any)],
        |(h, i, v): (i64, i64, Value)| {
            vec_with_mut(h, |items| {
                if i < 0 || i as usize >= items.len() {
                    return Err(format!("vec_set: index {i} out of range"));
                }
                items[i as usize] = v;
                Ok(true)
            })
            .ok_or_else(|| format!("vec_set: invalid handle {h}"))?
        },
    ));
    registry.register(native(
        "std.native.vec",
        "native_vec_len",
        Type::Int,
        &[("h", Type::Int)],
        |h: i64| Ok(vec_with(h, |items| items.len() as i64).unwrap_or(0)),
    ));
    registry.register(native(
        "std.native.vec",
        "native_vec_pop",
        Type::Any,
        &[("h", Type::Int)],
        |h: i64| {
            vec_with_mut(h, |items| items.pop())
                .ok_or_else(|| format!("vec_pop: invalid handle {h}"))?
                .ok_or_else(|| "vec_pop: vector is empty".to_string())
        },
    ));
    registry.register(native(
        "std.native.vec",
        "native_vec_clear",
        Type::Bool,
        &[("h", Type::Int)],
        |h: i64| {
            vec_with_mut(h, |items| {
                items.clear();
                true
            })
            .ok_or_else(|| format!("vec_clear: invalid handle {h}"))
        },
    ));
    registry.register(native(
        "std.native.vec",
        "native_vec_free",
        Type::Bool,
        &[("h", Type::Int)],
        |h: i64| {
            VEC_STORE.with(|s| {
                let mut store = s.borrow_mut();
                if h < 0 || h as usize >= store.len() || store[h as usize].is_none() {
                    return Err(format!("vec_free: invalid handle {h}"));
                }
                store[h as usize] = None;
                Ok(true)
            })
        },
    ));
    registry.register(native(
        "std.native.vec",
        "native_vec_insert",
        Type::Bool,
        &[("h", Type::Int), ("i", Type::Int), ("v", Type::Any)],
        |(h, i, v): (i64, i64, Value)| {
            vec_with_mut(h, |items| {
                let idx = i.max(0).min(items.len() as i64) as usize;
                items.insert(idx, v);
                true
            })
            .ok_or_else(|| format!("vec_insert: invalid handle {h}"))
        },
    ));
    registry.register(native(
        "std.native.vec",
        "native_vec_remove_at",
        Type::Bool,
        &[("h", Type::Int), ("i", Type::Int)],
        |(h, i): (i64, i64)| {
            vec_with_mut(h, |items| {
                if i < 0 || i as usize >= items.len() {
                    return Err(format!("vec_remove_at: index {i} out of range"));
                }
                items.remove(i as usize);
                Ok(true)
            })
            .ok_or_else(|| format!("vec_remove_at: invalid handle {h}"))?
        },
    ));

    // -- Bytes (domain: std.native.bytes) -------------------------------------
    registry.register(native(
        "std.native.bytes",
        "bytes_from_string",
        Type::Bytes,
        &[("s", Type::String)],
        |s: String| Ok(s.into_bytes()),
    ));
    registry.register(native(
        "std.native.bytes",
        "string_from_bytes",
        Type::String,
        &[("b", Type::Bytes)],
        |b: Vec<u8>| Ok(String::from_utf8_lossy(&b).into_owned()),
    ));
    registry.register(native(
        "std.native.bytes",
        "bytes_from_array",
        Type::Bytes,
        &[("arr", Type::Any)],
        |arr: Value| match arr {
            Value::Array { elements, .. } => {
                let mut out = Vec::with_capacity(elements.len());
                for el in elements {
                    let n = as_int(&el)?;
                    if !(0..=255).contains(&n) {
                        return Err(format!("bytes_from_array: {n} is not a byte"));
                    }
                    out.push(n as u8);
                }
                Ok(out)
            }
            other => Err(format!("bytes_from_array: expected [int], got {}", other.get_type())),
        },
    ));
    registry.register(native(
        "std.native.bytes",
        "array_from_bytes",
        Type::Array {
            element_type: Box::new(Type::Int),
            len: 0,
        },
        &[("b", Type::Bytes)],
        |b: Vec<u8>| {
            Ok(Value::Array {
                element_type: Type::Int,
                elements: b.into_iter().map(|x| Value::Int(x as i64)).collect(),
            })
        },
    ));

    // -- Filesystem (domain: std.native.fs) -----------------------------------
    registry.register(native(
        "std.native.fs",
        "native_fs_read",
        Type::String,
        &[("path", Type::String)],
        |path: String| {
            std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))
        },
    ));
    registry.register(native(
        "std.native.fs",
        "native_fs_write",
        Type::Bool,
        &[("path", Type::String), ("data", Type::String)],
        |(path, data): (String, String)| Ok(std::fs::write(&path, data).is_ok()),
    ));
    registry.register(native(
        "std.native.fs",
        "native_fs_read_b",
        Type::Bytes,
        &[("path", Type::String), ("max_len", Type::Int)],
        |(path, max_len): (String, i64)| {
            let data = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
            let limit = max_len.max(0) as usize;
            Ok(if limit == 0 { data } else { data[..data.len().min(limit)].to_vec() })
        },
    ));
    registry.register(native(
        "std.native.fs",
        "native_fs_write_b",
        Type::Bool,
        &[("path", Type::String), ("data", Type::Bytes)],
        |(path, data): (String, Vec<u8>)| Ok(std::fs::write(&path, data).is_ok()),
    ));
    registry.register(native(
        "std.native.fs",
        "native_fs_list_dir",
        Type::String,
        &[("path", Type::String)],
        |path: String| {
            let entries = match std::fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(_) => return Ok(String::new()),
            };
            let mut names: Vec<String> = Vec::new();
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    names.push(name);
                }
            }
            names.sort();
            Ok(names.join("\n"))
        },
    ));
    registry.register(native(
        "std.native.fs",
        "native_fs_create_dir",
        Type::Bool,
        &[("path", Type::String)],
        |path: String| Ok(std::fs::create_dir(&path).is_ok()),
    ));
    registry.register(native(
        "std.native.fs",
        "native_fs_remove",
        Type::Bool,
        &[("path", Type::String)],
        |path: String| {
            Ok(std::fs::remove_file(&path).is_ok() || std::fs::remove_dir(&path).is_ok())
        },
    ));
    registry.register(native(
        "std.native.fs",
        "native_fs_rename",
        Type::Bool,
        &[("old", Type::String), ("new", Type::String)],
        |(old, new): (String, String)| {
            if std::path::Path::new(&new).exists() {
                return Ok(false);
            }
            Ok(std::fs::rename(&old, &new).is_ok())
        },
    ));
    registry.register(native(
        "std.native.fs",
        "native_fs_is_dir",
        Type::Bool,
        &[("path", Type::String)],
        |path: String| Ok(std::path::Path::new(&path).is_dir()),
    ));
    registry.register(native(
        "std.native.fs",
        "native_fs_size",
        Type::Int,
        &[("path", Type::String)],
        |path: String| {
            Ok(std::fs::metadata(&path).map(|m| m.len() as i64).unwrap_or(0))
        },
    ));

    // -- Time (domain: std.native.time) ---------------------------------------
    registry.register(native(
        "std.native.time",
        "native_sleep",
        Type::Void,
        &[("ms", Type::Int)],
        |ms: i64| {
            if ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(ms as u64));
            }
            Ok(())
        },
    ));
    registry.register(native(
        "std.native.time",
        "native_get_ticks",
        Type::Int,
        &[],
        |_: ()| {
            use std::sync::OnceLock;
            static START: OnceLock<std::time::Instant> = OnceLock::new();
            let start = START.get_or_init(std::time::Instant::now);
            Ok(start.elapsed().as_millis() as i64)
        },
    ));

    // -- Process (domain: std.native.process) ---------------------------------
    let program_args = || -> String { String::new() };
    registry.register(native(
        "std.native.process",
        "native_get_pid",
        Type::Int,
        &[],
        |_: ()| Ok(std::process::id() as i64),
    ));
    registry.register(native(
        "std.native.process",
        "native_spawn",
        Type::Int,
        &[("name", Type::String)],
        |name: String| {
            match std::process::Command::new(&name).spawn() {
                Ok(child) => Ok(child.id() as i64),
                Err(_) => Ok(0),
            }
        },
    ));
    registry.register(native(
        "std.native.process",
        "native_exit",
        Type::Void,
        &[("code", Type::Int)],
        |code: i64| -> Result<(), String> {
            std::process::exit(code as i32);
        },
    ));
    registry.register(native(
        "std.native.process",
        "native_waitpid",
        Type::Int,
        &[("pid", Type::Int)],
        |_pid: i64| {
            Ok(-1)
        },
    ));
    registry.register(native(
        "std.native.process",
        "native_args",
        Type::String,
        &[],
        move |_: ()| Ok(program_args()),
    ));
}
