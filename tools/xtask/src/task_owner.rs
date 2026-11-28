//! A syntax-level ownership gate, not a Rust type checker. It follows the production module tree,
//! resolves use/type/extern-crate aliases, and checks async task launch sites (including macros).
//! Runtime handles and function pointers hidden behind unrelated APIs remain a review obligation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item, Meta, Pat, Token, Type, UseTree};

type Names = BTreeMap<String, String>;

struct Module {
    file: PathBuf,
    name: String,
    items: Vec<Item>,
}

#[derive(Clone, Default)]
struct Scope {
    module: String,
    aliases: Names,
    globs: Vec<String>,
    bindings: BTreeMap<String, Kind>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Runtime,
    LocalJoinSet,
    BorrowedJoinSet,
    Guard,
    Tracked,
    TrackedGuard,
    Other,
}

fn path(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|part| part.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn meta_arguments(meta: &syn::MetaList) -> Vec<Meta> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(meta.tokens.clone())
        .map(|items| items.into_iter().collect())
        .unwrap_or_default()
}

// Unknown features/platforms are inspected too; only predicates provably false without `test`
// are excluded. In particular cfg(any(test, feature = "live")) is NOT a test-only module.
fn predicate(meta: &Meta) -> Option<bool> {
    match meta {
        Meta::Path(name) if name.is_ident("test") => Some(false),
        Meta::List(list) if list.path.is_ident("not") => {
            predicate(meta_arguments(list).first()?).map(|v| !v)
        }
        Meta::List(list) if list.path.is_ident("all") || list.path.is_ident("any") => {
            let all = list.path.is_ident("all");
            let values: Vec<_> = meta_arguments(list).iter().map(predicate).collect();
            if values.contains(&Some(!all)) {
                Some(!all)
            } else if values.iter().all(Option::is_some) {
                Some(all)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn active(attrs: &[Attribute]) -> bool {
    attrs.iter().all(|attr| {
        if attr.path().is_ident("test") {
            return false;
        }
        let Meta::List(list) = &attr.meta else {
            return true;
        };
        if list.path.is_ident("cfg") {
            return meta_arguments(list).first().and_then(predicate) != Some(false);
        }
        if list.path.is_ident("cfg_attr") {
            let parts = meta_arguments(list);
            if parts.first().and_then(predicate) == Some(true) {
                return parts.iter().skip(1).all(|part| match part {
                    Meta::List(cfg) if cfg.path.is_ident("cfg") => {
                        meta_arguments(cfg).first().and_then(predicate) != Some(false)
                    }
                    _ => true,
                });
            }
        }
        true
    })
}

fn attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(v) => &v.attrs,
        Item::Enum(v) => &v.attrs,
        Item::ExternCrate(v) => &v.attrs,
        Item::Fn(v) => &v.attrs,
        Item::ForeignMod(v) => &v.attrs,
        Item::Impl(v) => &v.attrs,
        Item::Macro(v) => &v.attrs,
        Item::Mod(v) => &v.attrs,
        Item::Static(v) => &v.attrs,
        Item::Struct(v) => &v.attrs,
        Item::Trait(v) => &v.attrs,
        Item::TraitAlias(v) => &v.attrs,
        Item::Type(v) => &v.attrs,
        Item::Union(v) => &v.attrs,
        Item::Use(v) => &v.attrs,
        _ => &[],
    }
}

fn collect_modules(
    file: PathBuf,
    name: String,
    items: Option<Vec<Item>>,
    result: &mut Vec<Module>,
) -> Result<(), String> {
    let items = match items {
        Some(items) => items,
        None => {
            let source =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let parsed =
                syn::parse_file(&source).map_err(|e| format!("{}: {e}", file.display()))?;
            if !active(&parsed.attrs) {
                return Ok(());
            }
            parsed.items
        }
    };
    let directory = file.parent().ok_or("module has no parent")?;
    let default_dir = match file.file_stem().and_then(|s| s.to_str()) {
        Some("mod" | "lib" | "main") => directory.to_path_buf(),
        Some(stem) => directory.join(stem),
        None => return Err("module has no filename".into()),
    };
    collect_children(&file, &default_dir, &name, &items, result)?;
    result.push(Module { file, name, items });
    Ok(())
}

fn collect_children(
    file: &Path,
    module_dir: &Path,
    name: &str,
    items: &[Item],
    result: &mut Vec<Module>,
) -> Result<(), String> {
    for item in items {
        let Item::Mod(child) = item else { continue };
        if !active(&child.attrs) {
            continue;
        }
        let child_name = format!("{name}::{}", child.ident);
        if let Some((_, body)) = &child.content {
            collect_children(
                file,
                &module_dir.join(child.ident.to_string()),
                &child_name,
                body,
                result,
            )?;
            result.push(Module {
                file: file.to_path_buf(),
                name: child_name,
                items: body.clone(),
            });
            continue;
        }
        let explicit = child
            .attrs
            .iter()
            .find_map(|attribute| match &attribute.meta {
                Meta::NameValue(value) if value.path.is_ident("path") => match &value.value {
                    Expr::Lit(lit) => match &lit.lit {
                        syn::Lit::Str(s) => Some(s.value()),
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            });
        let child_file = if let Some(explicit) = explicit {
            file.parent().unwrap().join(explicit)
        } else {
            let single = module_dir.join(format!("{}.rs", child.ident));
            if single.is_file() {
                single
            } else {
                module_dir.join(child.ident.to_string()).join("mod.rs")
            }
        };
        collect_modules(child_file, child_name, None, result)?;
    }
    Ok(())
}

fn imports(tree: &UseTree, prefix: &str, aliases: &mut Names, globs: &mut Vec<String>) {
    let joined = |name: &str| {
        if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}::{name}")
        }
    };
    match tree {
        UseTree::Path(part) => {
            imports(&part.tree, &joined(&part.ident.to_string()), aliases, globs)
        }
        UseTree::Name(part) => {
            let value = if part.ident == "self" {
                prefix.to_string()
            } else {
                joined(&part.ident.to_string())
            };
            let key = if part.ident == "self" {
                prefix.rsplit("::").next().unwrap_or(prefix).to_string()
            } else {
                part.ident.to_string()
            };
            aliases.insert(key, value);
        }
        UseTree::Rename(part) => {
            aliases.insert(
                part.rename.to_string(),
                if part.ident == "self" {
                    prefix.to_string()
                } else {
                    joined(&part.ident.to_string())
                },
            );
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                imports(tree, prefix, aliases, globs);
            }
        }
        UseTree::Glob(_) => globs.push(prefix.to_string()),
    }
}

fn item_names(items: &[Item], scope: &mut Scope) {
    for item in items.iter().filter(|item| active(attributes(item))) {
        match item {
            Item::Use(item) => imports(&item.tree, "", &mut scope.aliases, &mut scope.globs),
            Item::ExternCrate(item) => {
                scope.aliases.insert(
                    item.rename
                        .as_ref()
                        .map_or(&item.ident, |(_, id)| id)
                        .to_string(),
                    item.ident.to_string(),
                );
            }
            Item::Type(item) => {
                if let Type::Path(ty) = &*item.ty {
                    scope.aliases.insert(item.ident.to_string(), path(&ty.path));
                }
            }
            _ => {}
        }
    }
}

fn relative(value: &str, module: &str) -> String {
    if let Some(tail) = value.strip_prefix("self::") {
        return format!("{module}::{tail}");
    }
    if value.starts_with("super::") {
        let mut context = module.to_string();
        let mut tail = value;
        while let Some(next) = tail.strip_prefix("super::") {
            context = context
                .rsplit_once("::")
                .map_or("crate", |(parent, _)| parent)
                .to_string();
            tail = next;
        }
        return format!("{context}::{tail}");
    }
    value.to_string()
}

fn resolve(name: &str, scope: &Scope, globals: &Names) -> String {
    let mut result = relative(name, &scope.module);
    let mut seen = BTreeSet::new();
    for _ in 0..32 {
        if !seen.insert(result.clone()) {
            break;
        }
        let (head, tail) = result.split_once("::").unwrap_or((&result, ""));
        if let Some(alias) = scope.aliases.get(head) {
            let replacement = relative(alias, &scope.module);
            let next = if tail.is_empty() {
                replacement
            } else {
                format!("{replacement}::{tail}")
            };
            if next != result {
                result = next;
                continue;
            }
        }
        let parts: Vec<_> = result.split("::").collect();
        let mut replacement = None;
        for length in (1..=parts.len()).rev() {
            if let Some(alias) = globals.get(&parts[..length].join("::")) {
                replacement = Some(if length == parts.len() {
                    alias.clone()
                } else {
                    format!("{alias}::{}", parts[length..].join("::"))
                });
                break;
            }
        }
        if let Some(next) = replacement
            && next != result
        {
            result = next;
            continue;
        }
        for glob in &scope.globs {
            let glob = relative(glob, &scope.module);
            let candidate = format!("{glob}::{result}");
            if globals.contains_key(&candidate)
                || matches!(
                    glob.as_str(),
                    "tokio" | "tokio::task" | "tokio::runtime" | "hyper_util::rt"
                )
            {
                result = candidate;
                break;
            }
        }
        break;
    }
    result
}

fn launch(name: &str) -> bool {
    matches!(
        name,
        "tokio::spawn"
            | "tokio::task::spawn"
            | "tokio::task::spawn_local"
            | "tokio::task::spawn_blocking"
    )
}

fn runtime(name: &str) -> bool {
    matches!(
        name,
        "tokio::runtime::Handle"
            | "tokio::runtime::Runtime"
            | "tokio::task::LocalSet"
            | "quinn::TokioRuntime"
    )
}

fn launcher_method(name: &str) -> bool {
    matches!(
        name,
        "spawn"
            | "spawn_on"
            | "spawn_local"
            | "spawn_local_on"
            | "spawn_blocking"
            | "spawn_blocking_on"
    )
}

fn self_field(expr: &Expr, aliases: &Names) -> Option<String> {
    match expr {
        Expr::Field(field) if matches!(&*field.base, Expr::Path(p) if p.path.is_ident("self")) => {
            Some(match &field.member {
                syn::Member::Named(name) => name.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            })
        }
        Expr::Path(expr) => aliases.get(&path(&expr.path)).cloned(),
        Expr::MethodCall(expr)
            if matches!(
                expr.method.to_string().as_str(),
                "take" | "get_mut" | "lock" | "as_ref" | "as_mut"
            ) =>
        {
            self_field(&expr.receiver, aliases)
        }
        Expr::Reference(expr) => self_field(&expr.expr, aliases),
        Expr::Paren(expr) => self_field(&expr.expr, aliases),
        _ => None,
    }
}

fn pat_idents(pat: &Pat, names: &mut Vec<String>) {
    match pat {
        Pat::Ident(pat) => names.push(pat.ident.to_string()),
        Pat::TupleStruct(pat) => {
            for pat in &pat.elems {
                pat_idents(pat, names);
            }
        }
        Pat::Tuple(pat) => {
            for pat in &pat.elems {
                pat_idents(pat, names);
            }
        }
        Pat::Reference(pat) => pat_idents(&pat.pat, names),
        Pat::Type(pat) => pat_idents(&pat.pat, names),
        _ => {}
    }
}

#[derive(Default)]
struct DropFields {
    aliases: Names,
    fields: BTreeSet<String>,
}

impl DropFields {
    fn alias(&mut self, pat: &Pat, value: &Expr) {
        if let Some(field) = self_field(value, &self.aliases) {
            let mut names = Vec::new();
            pat_idents(pat, &mut names);
            for name in names {
                self.aliases.insert(name, field.clone());
            }
        }
    }
}

impl<'ast> Visit<'ast> for DropFields {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(initializer) = &local.init {
            self.alias(&local.pat, &initializer.expr);
        }
        visit::visit_local(self, local);
    }
    fn visit_expr_let(&mut self, expr: &'ast syn::ExprLet) {
        self.alias(&expr.pat, &expr.expr);
        visit::visit_expr_let(self, expr);
    }
    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        if expr.method == "abort"
            && let Some(field) = self_field(&expr.receiver, &self.aliases)
        {
            self.fields.insert(field);
        }
        visit::visit_expr_method_call(self, expr);
    }
}

fn dropped_fields(items: &[Item]) -> BTreeMap<String, BTreeSet<String>> {
    let mut result = BTreeMap::new();
    for item in items {
        let Item::Impl(item) = item else { continue };
        if !active(&item.attrs)
            || !item.trait_.as_ref().is_some_and(|(_, name, _)| {
                name.segments
                    .last()
                    .is_some_and(|last| last.ident == "Drop")
            })
        {
            continue;
        }
        let Type::Path(ty) = &*item.self_ty else {
            continue;
        };
        let mut finder = DropFields::default();
        for member in &item.items {
            if let syn::ImplItem::Fn(method) = member
                && method.sig.ident == "drop"
                && active(&method.attrs)
            {
                finder.visit_block(&method.block);
            }
        }
        result.insert(path(&ty.path), finder.fields);
    }
    result
}

// Return only the task launch wrapped by an initializer. Do not give its spawned body the same
// exemption: an owner of an outer task does not own detached children.
#[derive(Default)]
struct RootLaunches {
    sites: BTreeSet<(usize, usize)>,
}

impl<'ast> Visit<'ast> for RootLaunches {
    fn visit_expr_call(&mut self, expr: &'ast syn::ExprCall) {
        if let Expr::Path(func) = &*expr.func
            && launch(&path(&func.path))
        {
            let start = func.path.span().start();
            self.sites.insert((start.line, start.column));
        } else {
            visit::visit_expr_call(self, expr);
        }
    }
    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        if launcher_method(&expr.method.to_string()) {
            let start = expr.method.span().start();
            self.sites.insert((start.line, start.column));
        } else {
            visit::visit_expr_method_call(self, expr);
        }
    }
    fn visit_item(&mut self, _: &'ast Item) {}
}

struct Ownership<'a> {
    owner: Option<&'a str>,
    dropped: &'a BTreeMap<String, BTreeSet<String>>,
    values: BTreeMap<String, BTreeSet<(usize, usize)>>,
    owned: BTreeSet<(usize, usize)>,
}

impl Ownership<'_> {
    fn from(&self, expr: &Expr) -> BTreeSet<(usize, usize)> {
        let site = |span: Span| BTreeSet::from([(span.start().line, span.start().column)]);
        match expr {
            Expr::Path(expr) => self
                .values
                .get(&path(&expr.path))
                .cloned()
                .unwrap_or_default(),
            Expr::Call(expr) => {
                if let Expr::Path(func) = &*expr.func {
                    let name = path(&func.path);
                    if launch(&name) {
                        return site(func.path.span());
                    }
                    if matches!(
                        name.as_str(),
                        "Some"
                            | "Option::Some"
                            | "Mutex::new"
                            | "tokio::sync::Mutex::new"
                            | "parking_lot::Mutex::new"
                    ) {
                        return expr.args.iter().flat_map(|arg| self.from(arg)).collect();
                    }
                }
                BTreeSet::new()
            }
            Expr::MethodCall(expr) => {
                let method = expr.method.to_string();
                if launcher_method(&method) {
                    return site(expr.method.span());
                }
                if matches!(method.as_str(), "map" | "and_then") {
                    return expr.args.iter().flat_map(|arg| self.from(arg)).collect();
                }
                if matches!(
                    method.as_str(),
                    "abort_handle" | "clone" | "unwrap" | "expect" | "ok"
                ) {
                    return self.from(&expr.receiver);
                }
                BTreeSet::new()
            }
            Expr::Block(expr) => match expr.block.stmts.last() {
                Some(syn::Stmt::Expr(expr, None)) => self.from(expr),
                _ => BTreeSet::new(),
            },
            Expr::Closure(expr) => self.from(&expr.body),
            Expr::Paren(expr) => self.from(&expr.expr),
            Expr::Group(expr) => self.from(&expr.expr),
            Expr::Try(expr) => self.from(&expr.expr),
            Expr::Reference(expr) => self.from(&expr.expr),
            _ => BTreeSet::new(),
        }
    }
    fn fields(&self, name: &syn::Path) -> Option<&BTreeSet<String>> {
        let name = path(name);
        self.dropped
            .get(if name == "Self" { self.owner? } else { &name })
    }
}

impl<'ast> Visit<'ast> for Ownership<'_> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init {
            let sites = self.from(&init.expr);
            let mut names = Vec::new();
            pat_idents(&local.pat, &mut names);
            for name in names {
                self.values.insert(name, sites.clone());
            }
        }
        visit::visit_local(self, local);
    }
    fn visit_expr_struct(&mut self, expr: &'ast syn::ExprStruct) {
        if let Some(fields) = self.fields(&expr.path).cloned() {
            for field in &expr.fields {
                let name = match &field.member {
                    syn::Member::Named(name) => name.to_string(),
                    syn::Member::Unnamed(index) => index.index.to_string(),
                };
                if fields.contains(&name) {
                    self.owned.extend(self.from(&field.expr));
                }
            }
        }
        visit::visit_expr_struct(self, expr);
    }
    fn visit_expr_call(&mut self, expr: &'ast syn::ExprCall) {
        if let Expr::Path(constructor) = &*expr.func
            && let Some(fields) = self.fields(&constructor.path).cloned()
        {
            for (index, arg) in expr.args.iter().enumerate() {
                if fields.contains(&index.to_string()) {
                    self.owned.extend(self.from(arg));
                }
            }
        }
        visit::visit_expr_call(self, expr);
    }
    fn visit_expr_async(&mut self, _: &'ast syn::ExprAsync) {}
    fn visit_item(&mut self, _: &'ast Item) {}
}

fn owned_sites(
    body: &syn::Block,
    owner: Option<&str>,
    dropped: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<(usize, usize)> {
    let mut ownership = Ownership {
        owner,
        dropped,
        values: BTreeMap::new(),
        owned: BTreeSet::new(),
    };
    ownership.visit_block(body);
    ownership.owned
}

struct Audit<'a> {
    scope: Scope,
    globals: &'a Names,
    file: &'a Path,
    problems: BTreeSet<(usize, String)>,
    owned: usize,
    awaited: usize,
    boundary: bool,
    owner_type: Option<String>,
    dropped_fields: &'a BTreeMap<String, BTreeSet<String>>,
    owned_sites: BTreeSet<(usize, usize)>,
}

impl Audit<'_> {
    fn report(&mut self, span: Span, message: impl Into<String>) {
        if !self.boundary {
            self.problems.insert((span.start().line, message.into()));
        }
    }

    fn name(&self, name: &syn::Path) -> String {
        resolve(&path(name), &self.scope, self.globals)
    }

    fn kind_type(&self, ty: &Type) -> Kind {
        match ty {
            Type::Reference(ty) => match self.kind_type(&ty.elem) {
                Kind::LocalJoinSet => Kind::BorrowedJoinSet,
                value => value,
            },
            Type::Path(ty) => {
                let name = self.name(&ty.path);
                if runtime(&name) {
                    Kind::Runtime
                } else if name == "tokio::task::JoinSet" {
                    Kind::LocalJoinSet
                } else {
                    Kind::Other
                }
            }
            _ => Kind::Other,
        }
    }

    fn kind(&self, expr: &Expr) -> Kind {
        match expr {
            Expr::Path(expr) => self
                .scope
                .bindings
                .get(&path(&expr.path))
                .copied()
                .unwrap_or_else(|| {
                    if runtime(&self.name(&expr.path)) {
                        Kind::Runtime
                    } else {
                        Kind::Other
                    }
                }),
            Expr::Call(expr) => {
                if let Expr::Path(call) = &*expr.func {
                    let name = self.name(&call.path);
                    if matches!(
                        name.as_str(),
                        "crate::network_tasks::spawn" | "crate::network_tasks::spawn_in"
                    ) {
                        return Kind::Tracked;
                    }
                    let parent = name.rsplit_once("::").map_or("", |(parent, _)| parent);
                    if runtime(parent) {
                        return Kind::Runtime;
                    }
                    if parent == "tokio::task::JoinSet" {
                        return Kind::LocalJoinSet;
                    }
                    if parent == "tokio_util::task::AbortOnDropHandle" {
                        return if expr
                            .args
                            .first()
                            .is_some_and(|arg| self.kind(arg) == Kind::Tracked)
                        {
                            Kind::TrackedGuard
                        } else {
                            Kind::Guard
                        };
                    }
                }
                Kind::Other
            }
            Expr::MethodCall(expr) => self.kind(&expr.receiver),
            Expr::Reference(expr) => self.kind(&expr.expr),
            Expr::Try(expr) => self.kind(&expr.expr),
            Expr::Paren(expr) => self.kind(&expr.expr),
            Expr::Group(expr) => self.kind(&expr.expr),
            _ => Kind::Other,
        }
    }

    fn bind(&mut self, pat: &Pat, kind: Kind) {
        match pat {
            Pat::Ident(pat) => {
                self.scope.bindings.insert(pat.ident.to_string(), kind);
            }
            Pat::Type(pat) => self.bind(&pat.pat, self.kind_type(&pat.ty)),
            _ => {}
        }
    }

    fn signature(&mut self, signature: &syn::Signature) {
        for parameter in &signature.inputs {
            if let syn::FnArg::Typed(parameter) = parameter {
                self.bind(&parameter.pat, self.kind_type(&parameter.ty));
            }
        }
    }

    fn check_path(&mut self, path: &syn::Path) {
        let name = self.name(path);
        if launch(&name)
            && self.owned == 0
            && !self.site_owned(path.span())
            && !(name.ends_with("spawn_blocking") && self.awaited > 0)
        {
            self.report(
                path.span(),
                format!("{name} can outlive its owner; use NetworkTasks or an abort-on-drop guard"),
            );
        }
        if name == "hyper_util::rt::TokioExecutor"
            || name.starts_with("hyper_util::rt::TokioExecutor::")
        {
            self.report(
                path.span(),
                "TokioExecutor starts detached HTTP tasks; use the tracked executor",
            );
        }
    }

    fn site_owned(&self, span: Span) -> bool {
        self.owned_sites
            .contains(&(span.start().line, span.start().column))
    }

    fn function(&mut self, signature: &syn::Signature, body: &syn::Block) {
        let previous = self.scope.clone();
        let previous_sites = std::mem::take(&mut self.owned_sites);
        self.signature(signature);
        self.owned_sites = owned_sites(body, self.owner_type.as_deref(), self.dropped_fields);
        // These are process/service entry points with explicit shutdown protocols, not leaf
        // protocol launch sites. A second launch in any one is a new error, not grandfathered.
        let reviewed = match (
            self.scope.module.as_str(),
            self.owner_type.as_deref(),
            signature.ident.to_string().as_str(),
        ) {
            ("crate::embedding", Some("EmbeddedCore"), "start_cancellable") => Some(
                "EmbeddedCore owns the command channel; Process::run stops when all senders close",
            ),
            ("crate::ffi::common", None, "spawn_service") => Some(
                "TunServiceHandle owns the runtime and shutdown receiver; its caller joins the service",
            ),
            ("crate::wireguard", Some("PreparedEndpoint"), "start") => Some(
                "EndpointRuntime cancels on Drop and Running::stop awaits device and socket retirement",
            ),
            ("crate::certificates::runtime", Some("Registry"), "start")
                if self
                    .dropped_fields
                    .get("Worker")
                    .is_some_and(|fields| fields.contains("task")) =>
            {
                Some(
                    "Registry stores each task in Worker.task, whose Drop aborts it and stop_task joins it",
                )
            }
            _ => None,
        };
        if let Some(reason) = reviewed {
            let mut roots = RootLaunches::default();
            roots.visit_block(body);
            if roots.sites.len() == 1 {
                self.owned_sites.extend(roots.sites);
            } else {
                self.report(
                    signature.ident.span(),
                    format!(
                        "reviewed owner boundary changed ({} launch sites): {reason}",
                        roots.sites.len()
                    ),
                );
            }
        }
        self.visit_block(body);
        self.scope = previous;
        self.owned_sites = previous_sites;
    }

    fn macro_tokens(&mut self, tokens: TokenStream) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        let mut index = 0;
        while index < tokens.len() {
            if let TokenTree::Group(group) = &tokens[index] {
                if let Ok(block) =
                    syn::parse2::<syn::Block>(TokenStream::from(TokenTree::Group(group.clone())))
                {
                    self.visit_block(&block);
                } else {
                    self.macro_tokens(group.stream());
                }
            }
            if let TokenTree::Ident(first) = &tokens[index] {
                let mut names = vec![first.to_string()];
                let mut end = index + 1;
                while end + 2 < tokens.len() {
                    if matches!(&tokens[end], TokenTree::Punct(p) if p.as_char() == ':')
                        && matches!(&tokens[end+1], TokenTree::Punct(p) if p.as_char() == ':')
                        && let TokenTree::Ident(next) = &tokens[end + 2]
                    {
                        names.push(next.to_string());
                        end += 3;
                    } else {
                        break;
                    }
                }
                let name = resolve(&names.join("::"), &self.scope, self.globals);
                if launch(&name) || name.starts_with("hyper_util::rt::TokioExecutor") {
                    self.report(first.span(), format!("{name} in a macro bypasses task ownership; move launch into a checked helper"));
                }
                if end == index + 1
                    && end + 1 < tokens.len()
                    && matches!(&tokens[end], TokenTree::Punct(p) if p.as_char() == '.')
                    && let TokenTree::Ident(method) = &tokens[end + 1]
                    && launcher_method(&method.to_string())
                    && self.scope.bindings.get(&first.to_string()) == Some(&Kind::Runtime)
                {
                    self.report(
                        first.span(),
                        "runtime task launch in a macro bypasses task ownership",
                    );
                }
                index = end;
            } else {
                index += 1;
            }
        }
    }
}

impl<'ast> Visit<'ast> for Audit<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if active(attributes(item)) && !matches!(item, Item::Mod(_)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.function(&item.sig, &item.block);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !active(&item.attrs) {
            return;
        }
        self.function(&item.sig, &item.block);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let previous = self.owner_type.clone();
        self.owner_type = if let Type::Path(ty) = &*item.self_ty {
            Some(path(&ty.path))
        } else {
            None
        };
        visit::visit_item_impl(self, item);
        self.owner_type = previous;
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let previous = self.scope.clone();
        let items: Vec<_> = block
            .stmts
            .iter()
            .filter_map(|stmt| {
                if let syn::Stmt::Item(item) = stmt {
                    Some(item.clone())
                } else {
                    None
                }
            })
            .collect();
        item_names(&items, &mut self.scope);
        visit::visit_block(self, block);
        self.scope = previous;
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if !active(&local.attrs) {
            return;
        }
        if let Some(initializer) = &local.init {
            self.visit_expr(&initializer.expr);
            self.bind(&local.pat, self.kind(&initializer.expr));
            if let Some((_, diverge)) = &initializer.diverge {
                self.visit_expr(diverge);
            }
        } else {
            self.bind(&local.pat, Kind::Other);
        }
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        self.check_path(&expr.path);
    }

    fn visit_expr_await(&mut self, expr: &'ast syn::ExprAwait) {
        self.awaited += 1;
        self.visit_expr(&expr.base);
        self.awaited -= 1;
    }

    fn visit_expr_call(&mut self, expr: &'ast syn::ExprCall) {
        let guard = matches!(&*expr.func, Expr::Path(path) if self.name(&path.path) == "tokio_util::task::AbortOnDropHandle::new");
        if matches!(&*expr.func, Expr::Path(path) if matches!(self.name(&path.path).as_str(), "std::mem::forget" | "core::mem::forget" | "std::mem::ManuallyDrop::new" | "core::mem::ManuallyDrop::new"))
            && expr
                .args
                .iter()
                .any(|arg| matches!(self.kind(arg), Kind::LocalJoinSet | Kind::Guard))
        {
            self.report(
                expr.span(),
                "forgetting a task owner prevents its cancellation on Drop",
            );
        }
        self.visit_expr(&expr.func);
        for arg in &expr.args {
            if guard {
                self.owned += 1;
            }
            self.visit_expr(arg);
            if guard {
                self.owned -= 1;
            }
        }
    }

    fn visit_expr_async(&mut self, expr: &'ast syn::ExprAsync) {
        // An outer guard/await owns its task only, not tasks launched from inside its body.
        let previous = (self.owned, self.awaited);
        self.owned = 0;
        self.awaited = 0;
        visit::visit_expr_async(self, expr);
        (self.owned, self.awaited) = previous;
    }

    fn visit_expr_closure(&mut self, expr: &'ast syn::ExprClosure) {
        let previous = (self.owned, self.awaited);
        self.owned = 0;
        self.awaited = 0;
        visit::visit_expr_closure(self, expr);
        (self.owned, self.awaited) = previous;
    }

    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        let kind = self.kind(&expr.receiver);
        let method = expr.method.to_string();
        if launcher_method(&method)
            && kind == Kind::Runtime
            && self.owned == 0
            && !self.site_owned(expr.method.span())
            && !(method.starts_with("spawn_blocking") && self.awaited > 0)
        {
            self.report(expr.method.span(), "runtime task launch can outlive its owner; use NetworkTasks or an abort-on-drop guard");
        }
        if launcher_method(&method) && kind == Kind::BorrowedJoinSet {
            self.report(
                expr.method.span(),
                "borrowed JoinSet ownership is not local; use network_tasks::spawn_in",
            );
        }
        if matches!(method.as_str(), "detach_all" | "forget") && kind == Kind::LocalJoinSet {
            self.report(
                expr.method.span(),
                "detaching a JoinSet loses its task ownership",
            );
        }
        if matches!(method.as_str(), "detach" | "into_inner") && kind == Kind::Guard {
            self.report(
                expr.method.span(),
                "removing the task guard loses its ownership",
            );
        }
        self.visit_expr(&expr.receiver);
        for argument in &expr.args {
            if matches!(method.as_str(), "map" | "and_then")
                && kind == Kind::Runtime
                && let Expr::Closure(closure) = argument
            {
                let previous = self.scope.clone();
                for parameter in &closure.inputs {
                    self.bind(parameter, Kind::Runtime);
                }
                self.visit_expr_closure(closure);
                self.scope = previous;
            } else {
                self.visit_expr(argument);
            }
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.macro_tokens(mac.tokens.clone());
    }
}

pub fn check(entry: &Path) -> Result<usize, String> {
    let mut modules = Vec::new();
    collect_modules(entry.to_path_buf(), "crate".into(), None, &mut modules)?;
    let mut globals = Names::new();
    for module in &modules {
        let mut scope = Scope {
            module: module.name.clone(),
            ..Scope::default()
        };
        item_names(&module.items, &mut scope);
        for (name, value) in &scope.aliases {
            globals.insert(
                format!("{}::{name}", module.name),
                relative(value, &module.name),
            );
        }
    }
    let mut problems = BTreeSet::new();
    for module in &modules {
        let mut scope = Scope {
            module: module.name.clone(),
            ..Scope::default()
        };
        item_names(&module.items, &mut scope);
        // These two modules implement the tracker and Quinn's runtime adapter themselves.
        // Protocol handlers cannot opt into this exception via an annotation or directory name.
        let boundary = matches!(
            module.name.as_str(),
            "crate::network_tasks" | "crate::quic_endpoint"
        );
        let dropped_fields = dropped_fields(&module.items);
        let mut audit = Audit {
            scope,
            globals: &globals,
            file: &module.file,
            problems: BTreeSet::new(),
            owned: 0,
            awaited: 0,
            boundary,
            owner_type: None,
            dropped_fields: &dropped_fields,
            owned_sites: BTreeSet::new(),
        };
        for item in &module.items {
            audit.visit_item(item);
        }
        for (line, message) in audit.problems {
            problems.insert(format!("{}:{line}: {message}", audit.file.display()));
        }
    }
    if problems.is_empty() {
        Ok(modules.len())
    } else {
        Err(problems.into_iter().collect::<Vec<_>>().join("\n"))
    }
}

#[cfg(test)]
mod tests;
