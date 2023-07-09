use itertools::Itertools;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

const GREY: ansi_term::Colour = ansi_term::Colour::Fixed(244);

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
        if !children.0.is_empty() {
            self.0.push(Entry { data, children });
        }
        self
    }
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn render(&self, mw: Option<usize>, color: bool, ret: &mut impl FnMut(&[u8])) {
        for entry in &self.0 {
            render_entry(entry, mw, color, ret, None);
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
    color: bool,
    ret: &mut impl FnMut(&[u8]),
    prefix: Option<&Prefix<'_>>,
) {
    if color {
        let mut out = String::new();
        render_pfx(prefix, true, &mut |s| out.push_str(s));
        ret(format!("{}", GREY.paint(out)).as_bytes());
    } else {
        render_pfx(prefix, true, &mut |s| ret(s.as_bytes()));
    }
    let mut out = String::new();
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
    let collapsed = collapse(&tree.children.0, mw.map(|mw| mw - out.width()), color);
    if let Some(collapsed) = &collapsed {
        out.push_str(collapsed);
    }
    ret(out.as_bytes());
    ret(b"\n");
    if collapsed.is_none() {
        for child in tree.children.0.iter().with_position() {
            let last = matches!(
                child,
                itertools::Position::Last(_) | itertools::Position::Only(_)
            );
            let child = child.into_inner();
            let prefix = Prefix { last, prefix };
            render_entry(child, mw, color, ret, Some(&prefix));
        }
    }
}

fn collapse(children: &[Entry], mw: Option<usize>, color: bool) -> Option<String> {
    let sep = if color {
        format!("{}", GREY.paint(" / "))
    } else {
        " / ".into()
    };
    match &children {
        &[Entry { data, children }] => {
            let nw = data.width() + sep.width();
            if mw.map_or_else(|| true, |mw| nw <= mw) {
                if children.0.is_empty() {
                    Some(format!("{sep}{data}"))
                } else {
                    Some(format!(
                        "{sep}{data}{}",
                        collapse(&children.0, mw.map(|mw| mw.saturating_sub(nw)), color)?
                    ))
                }
            } else {
                None
            }
        }
        _ => None,
    }
}
