//! Syntax-aware Rust metrics.

use crate::limits::{MAX_COMPLEXITY, MAX_FUNCTION_LINES, MAX_NESTING, MAX_PARAMETERS, MAX_TYPE_LINES};
use proc_macro2::Span;
use std::path::Path;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ImplItemFn, ItemEnum, ItemFn, ItemImpl, ItemStruct, ItemTrait};

pub(crate) fn inspect(path: &Path, syntax: &syn::File) -> Vec<String> {
    let mut visitor = MetricsVisitor {
        path,
        violations: Vec::new(),
        depth: 0,
        maximum_depth: 0,
        complexity: 0,
    };
    visitor.visit_file(syntax);
    visitor.violations
}

struct MetricsVisitor<'a> {
    path: &'a Path,
    violations: Vec<String>,
    depth: usize,
    maximum_depth: usize,
    complexity: usize,
}

impl MetricsVisitor<'_> {
    fn inspect_function(&mut self, name: &str, span: Span, parameters: usize, body: &syn::Block) {
        check_lines(
            &mut self.violations,
            self.path,
            "function",
            name,
            span,
            MAX_FUNCTION_LINES,
        );
        if parameters > MAX_PARAMETERS {
            self.violate(
                name,
                &format!("has {parameters} parameters; maximum is {MAX_PARAMETERS}"),
            );
        }
        let previous_depth = self.depth;
        let previous_maximum = self.maximum_depth;
        let previous_complexity = self.complexity;
        self.depth = 0;
        self.maximum_depth = 0;
        self.complexity = 1;
        visit::visit_block(self, body);
        if self.complexity > MAX_COMPLEXITY {
            self.violate(
                name,
                &format!(
                    "has cyclomatic complexity {}; maximum is {MAX_COMPLEXITY}",
                    self.complexity
                ),
            );
        }
        if self.maximum_depth > MAX_NESTING {
            self.violate(
                name,
                &format!(
                    "has control-flow nesting {}; maximum is {MAX_NESTING}",
                    self.maximum_depth
                ),
            );
        }
        self.depth = previous_depth;
        self.maximum_depth = previous_maximum;
        self.complexity = previous_complexity;
    }

    fn enter_control(&mut self, expression: &Expr) {
        self.complexity += 1;
        self.depth += 1;
        self.maximum_depth = self.maximum_depth.max(self.depth);
        visit::visit_expr(self, expression);
        self.depth -= 1;
    }

    fn violate(&mut self, name: &str, detail: &str) {
        self.violations
            .push(format!("{}: {name} {detail}", self.path.display()));
    }
}

impl<'ast> Visit<'ast> for MetricsVisitor<'_> {
    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        self.inspect_function(
            &function.sig.ident.to_string(),
            function.span(),
            function.sig.inputs.len(),
            &function.block,
        );
    }

    fn visit_impl_item_fn(&mut self, function: &'ast ImplItemFn) {
        self.inspect_function(
            &function.sig.ident.to_string(),
            function.span(),
            function.sig.inputs.len(),
            &function.block,
        );
    }

    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        check_lines(
            &mut self.violations,
            self.path,
            "struct",
            &item.ident.to_string(),
            item.span(),
            MAX_TYPE_LINES,
        );
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast ItemEnum) {
        check_lines(
            &mut self.violations,
            self.path,
            "enum",
            &item.ident.to_string(),
            item.span(),
            MAX_TYPE_LINES,
        );
        visit::visit_item_enum(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast ItemTrait) {
        check_lines(
            &mut self.violations,
            self.path,
            "trait",
            &item.ident.to_string(),
            item.span(),
            MAX_TYPE_LINES,
        );
        visit::visit_item_trait(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        check_lines(
            &mut self.violations,
            self.path,
            "impl",
            "block",
            item.span(),
            MAX_TYPE_LINES,
        );
        visit::visit_item_impl(self, item);
    }

    fn visit_expr(&mut self, expression: &'ast Expr) {
        if matches!(
            expression,
            Expr::If(_) | Expr::ForLoop(_) | Expr::While(_) | Expr::Loop(_) | Expr::Match(_)
        ) {
            self.enter_control(expression);
            return;
        }
        if let Expr::Binary(binary) = expression
            && matches!(binary.op, syn::BinOp::And(_) | syn::BinOp::Or(_))
        {
            self.complexity += 1;
        }
        visit::visit_expr(self, expression);
    }
}

fn check_lines(violations: &mut Vec<String>, path: &Path, kind: &str, name: &str, span: Span, maximum: usize) {
    let start = span.start().line;
    let end = span.end().line;
    let lines = end.saturating_sub(start) + 1;
    if lines > maximum {
        violations.push(format!(
            "{}: {kind} {name} has {lines} lines; maximum is {maximum}",
            path.display()
        ));
    }
}
