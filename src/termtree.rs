use itertools::Itertools;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub struct Tree(Vec<Entry>);
pub struct Entry {
    pub data: String,
    pub children: Tree,
}
impl Tree {
    pub fn leaf(&mut self, data: String) -> &mut Self {
        self.0.push(Entry {
            data,
            children: Tree::new(),
        });
        self
    }
    pub fn node(&mut self, data: String, children: Tree) -> &mut Self {
        self.0.push(Entry { data, children });
        self
    }
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn render(&self, mw: Option<usize>, ret: &mut impl FnMut(&str)) {
        for entry in &self.0 {
            render_entry(entry, mw, ret, None);
        }
    }
}

struct Prefix<'a> {
    last: bool,
    prefix: Option<&'a Prefix<'a>>,
}

fn render_pfx(prefix: Option<&Prefix>, rightmost: bool, ret: &mut impl FnMut(&str)) {
    if let Some(prefix) = prefix {
        render_pfx(prefix.prefix, false, ret);
        match (rightmost, prefix.last) {
            (false, true) => ret("  "),
            (false, false) => ret("│ "),
            (true, true) => ret("└ "),
            (true, false) => ret("├ "),
        }
    }
}

fn render_entry(
    tree: &Entry,
    mw: Option<usize>,
    ret: &mut impl FnMut(&str),
    prefix: Option<&Prefix<'_>>,
) {
    let mut out = String::new();
    render_pfx(prefix, true, &mut |s| out.push_str(s));
    if let Some(mw) = mw {
        if out.width() + tree.data.width() <= mw {
            out.push_str(&tree.data);
        } else {
            for c in tree.data.chars() {
                if out.width() + c.width().unwrap_or(0) < mw {
                    out.push(c);
                } else {
                    break;
                }
            }
            while out.width() < mw {
                out.push('…');
            }
        }
    } else {
        out.push_str(&tree.data);
    }
    ret(&out);
    for child in tree.children.0.iter().with_position() {
        let last = matches!(
            child,
            itertools::Position::Last(_) | itertools::Position::Only(_)
        );
        let child = child.into_inner();
        let prefix = Prefix { last, prefix };
        render_entry(child, mw, ret, Some(&prefix));
    }
}
