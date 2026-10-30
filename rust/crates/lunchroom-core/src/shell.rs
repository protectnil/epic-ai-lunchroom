//! A strict reader for shell command text.
//!
//! Spec §12 F1.2: "A command the guard cannot parse" is judged by its words alone. This reader
//! accepts only plain commands: words, quotes, escapes, `$HOME`, a leading `~`, the separators
//! `; & && || | |&` and redirections. Anything whose meaning the guard cannot read from the text
//! (substitution, other variables, heredocs, subshells, groups, brace expansion, control words,
//! unterminated quotes) makes the whole text unparsed.

/// One word of a command, after quotes and escapes are removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    /// The word's text.
    pub text: String,
    /// It has an unquoted `*`, `?` or `[`, so the shell may expand it.
    pub glob: bool,
    /// It names a redirection's target (`> file`), not an argument.
    pub redirect: bool,
}

/// One simple command: its words in order, redirection targets included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Command {
    /// The words.
    pub words: Vec<Word>,
}

/// The result of reading a command text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Plain commands, in order.
    Commands(Vec<Command>),
    /// The guard cannot tell what the text runs.
    Unparsed,
}

/// Words that start shell control syntax.
const RESERVED: [&str; 20] = [
    "if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while", "until", "do",
    "done", "function", "[[", "]]", "!", "{", "}", "coproc",
];

/// Reads `text`; `home` is what `$HOME`, `${HOME}` and a leading `~` stand for.
#[must_use]
pub fn parse(text: &str, home: &str) -> Parsed {
    let mut lx = Lexer::new(text, home);
    match lx.run() {
        Some(()) => Parsed::Commands(lx.cmds),
        None => Parsed::Unparsed,
    }
}

/// The one command of a text that is exactly one plain command: no separator, no second line
/// and no redirection (§6 item 1: a reply is a command that is exactly one `lunchroom send`).
#[must_use]
pub fn single(text: &str, home: &str) -> Option<Command> {
    let mut lx = Lexer::new(text, home);
    lx.run()?;
    if lx.joined || lx.cmds.len() != 1 {
        return None;
    }
    lx.cmds.pop()
}

struct Lexer<'a> {
    s: Vec<char>,
    i: usize,
    home: &'a str,
    cmds: Vec<Command>,
    cur: Command,
    /// The current command has a word that is not an assignment.
    named: bool,
    /// The last separator needs a command after it (`|`, `&&`, `||`, `|&`).
    continued: bool,
    /// The text has a separator or a redirection.
    joined: bool,
}

fn is_blank(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn ends_word(c: char) -> bool {
    is_blank(c) || matches!(c, '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')')
}

fn is_assignment(w: &str) -> bool {
    let Some((name, _)) = w.split_once('=') else {
        return false;
    };
    let mut cs = name.chars();
    cs.next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl<'a> Lexer<'a> {
    fn new(text: &str, home: &'a str) -> Self {
        Lexer {
            s: text.chars().collect(),
            i: 0,
            home,
            cmds: Vec::new(),
            cur: Command::default(),
            named: false,
            continued: false,
            joined: false,
        }
    }

    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn at(&self, k: usize) -> Option<char> {
        self.s.get(self.i + k).copied()
    }

    fn skip_blanks(&mut self) {
        loop {
            match self.peek() {
                Some(c) if is_blank(c) => self.i += 1,
                Some('\\') if self.at(1) == Some('\n') => self.i += 2,
                _ => return,
            }
        }
    }

    fn run(&mut self) -> Option<()> {
        loop {
            self.skip_blanks();
            let Some(c) = self.peek() else { break };
            match c {
                '#' => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.i += 1;
                    }
                }
                '\n' => {
                    self.i += 1;
                    if !self.continued {
                        self.end_command(false)?;
                    }
                }
                ';' => {
                    self.i += 1;
                    self.joined = true;
                    self.end_command(true)?;
                }
                '&' if self.at(1) == Some('&') => self.separator(2, true)?,
                '&' if self.at(1) == Some('>') => {
                    self.i += if self.at(2) == Some('>') { 3 } else { 2 };
                    self.joined = true;
                    self.target()?;
                }
                '&' => self.separator(1, false)?,
                '|' if matches!(self.at(1), Some('|' | '&')) => self.separator(2, true)?,
                '|' => self.separator(1, true)?,
                '<' | '>' => self.redirection(c)?,
                '(' | ')' => return None,
                _ => {
                    let w = self.word()?;
                    self.push(w)?;
                }
            }
        }
        if self.continued {
            return None;
        }
        self.end_command(false)
    }

    fn separator(&mut self, len: usize, continued: bool) -> Option<()> {
        self.i += len;
        self.joined = true;
        self.end_command(true)?;
        self.continued = continued;
        Some(())
    }

    /// Ends the current command. `strict`: a separator with no command before it is a syntax error.
    fn end_command(&mut self, strict: bool) -> Option<()> {
        if self.cur.words.is_empty() {
            if strict {
                return None;
            }
        } else {
            self.cmds.push(std::mem::take(&mut self.cur));
            self.named = false;
        }
        self.continued = false;
        Some(())
    }

    fn redirection(&mut self, c: char) -> Option<()> {
        self.joined = true;
        match (c, self.at(1)) {
            (_, Some('(')) => None,
            ('<', Some('<')) => {
                if self.at(2) == Some('<') {
                    self.i += 3;
                    self.target()
                } else {
                    None // a heredoc: its body is not a command the guard can read
                }
            }
            (_, Some('&')) => {
                self.i += 2;
                if self.peek().is_some_and(|d| d.is_ascii_digit() || d == '-') {
                    while self.peek().is_some_and(|d| d.is_ascii_digit() || d == '-') {
                        self.i += 1;
                    }
                    Some(())
                } else {
                    self.target()
                }
            }
            ('>', Some('>' | '|')) | ('<', Some('>')) => {
                self.i += 2;
                self.target()
            }
            _ => {
                self.i += 1;
                self.target()
            }
        }
    }

    /// The word a redirection names; it is kept with the command's words.
    fn target(&mut self) -> Option<()> {
        self.skip_blanks();
        match self.peek() {
            Some(c) if !ends_word(c) => {
                let (mut w, _) = self.word()?;
                w.redirect = true;
                self.cur.words.push(w);
                self.continued = false;
                Some(())
            }
            _ => None,
        }
    }

    fn push(&mut self, w: (Word, bool)) -> Option<()> {
        let (word, quoted) = w;
        // A number right before `<` or `>` is the redirected file descriptor, not a word.
        if !quoted
            && !word.text.is_empty()
            && word.text.chars().all(|c| c.is_ascii_digit())
            && matches!(self.peek(), Some('<' | '>'))
        {
            return Some(());
        }
        if !self.named {
            if !quoted && RESERVED.contains(&word.text.as_str()) {
                return None;
            }
            if quoted || !is_assignment(&word.text) {
                self.named = true;
            }
        }
        self.cur.words.push(word);
        self.continued = false;
        Some(())
    }

    /// Reads one word. Returns the word and whether any part of it was quoted or escaped.
    fn word(&mut self) -> Option<(Word, bool)> {
        let mut text = String::new();
        let mut glob = false;
        let mut quoted = false;
        let mut braces: Vec<usize> = Vec::new();
        let start = self.i;
        while let Some(c) = self.peek() {
            if ends_word(c) {
                break;
            }
            self.i += 1;
            match c {
                '\\' => match self.peek() {
                    None => return None,
                    Some('\n') => self.i += 1,
                    Some(n) => {
                        text.push(n);
                        quoted = true;
                        self.i += 1;
                    }
                },
                '\'' => {
                    quoted = true;
                    loop {
                        let n = self.peek()?;
                        self.i += 1;
                        if n == '\'' {
                            break;
                        }
                        text.push(n);
                    }
                }
                '"' => {
                    quoted = true;
                    self.double_quoted(&mut text)?;
                }
                '$' => self.dollar(&mut text, false)?,
                '`' => return None,
                '*' | '?' | '[' => {
                    glob = true;
                    text.push(c);
                }
                '{' => {
                    braces.push(text.len());
                    text.push(c);
                }
                '}' => {
                    if let Some(open) = braces.pop() {
                        let inner = &text[open..];
                        if inner.contains(',') || inner.contains("..") {
                            return None; // brace expansion
                        }
                    }
                    text.push(c);
                }
                '~' if self.i - 1 == start => match self.peek() {
                    None | Some('/') => text.push_str(self.home),
                    Some(n) if ends_word(n) => text.push_str(self.home),
                    Some(_) => return None, // ~user, ~+, ~-
                },
                _ => text.push(c),
            }
        }
        let word = Word {
            text,
            glob,
            redirect: false,
        };
        Some((word, quoted))
    }

    fn double_quoted(&mut self, text: &mut String) -> Option<()> {
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                '"' => return Some(()),
                '\\' => {
                    let n = self.peek()?;
                    self.i += 1;
                    match n {
                        '\n' => {}
                        '$' | '`' | '"' | '\\' => text.push(n),
                        _ => {
                            text.push('\\');
                            text.push(n);
                        }
                    }
                }
                '$' => self.dollar(text, true)?,
                '`' => return None,
                _ => text.push(c),
            }
        }
    }

    /// After a `$`: only `$HOME` and `${HOME}` are read; a lone `$` is literal; anything else is
    /// unparsed. `in_quotes`: inside double quotes, where `$"` is a literal `$` and the closing quote.
    fn dollar(&mut self, text: &mut String, in_quotes: bool) -> Option<()> {
        match self.peek() {
            None => text.push('$'),
            Some('"' | '\'') if !in_quotes => return None, // $"..." and $'...'
            Some('(') => return None,                      // $(...) and $((...)), quoted or not
            Some(c) if ends_word(c) || c == '"' => text.push('$'),
            Some('{') => {
                let rest: String = self.s[self.i..].iter().take(6).collect();
                if rest != "{HOME}" {
                    return None;
                }
                self.i += 6;
                text.push_str(self.home);
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                let mut name = String::new();
                while let Some(n) = self
                    .peek()
                    .filter(|n| n.is_ascii_alphanumeric() || *n == '_')
                {
                    name.push(n);
                    self.i += 1;
                }
                if name != "HOME" {
                    return None;
                }
                text.push_str(self.home);
            }
            Some(_) => return None,
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The words of each command; an unparsed text gives one command with the word `UNPARSED`.
    fn words(text: &str) -> Vec<Vec<String>> {
        match parse(text, "/home/u") {
            Parsed::Commands(cs) => cs
                .into_iter()
                .map(|c| c.words.into_iter().map(|w| w.text).collect())
                .collect(),
            Parsed::Unparsed => vec![vec!["UNPARSED".to_owned()]],
        }
    }

    // §6 item 1: exactly one plain command; any separator, second line or redirection is not.
    #[test]
    fn single_command_only() {
        let one = |t: &str| single(t, "/home/u").map(|c| c.words.len());
        assert_eq!(one("lunchroom send a 'x; y'"), Some(4));
        assert_eq!(one("lunchroom send a hi # note\n"), Some(4));
        for t in [
            "a; b", "a;", "a && b", "a || b", "a | b", "a |& b", "a &", "a\nb", "a > f", "a >> f",
            "a < f", "a 2>&1", "a &> f", "a <<< x", "a $(b)", "",
        ] {
            assert_eq!(one(t), None, "{t}");
        }
    }

    // §12 F1.2: the forms the guard reads.
    #[test]
    fn f1_plain_commands_parse() {
        assert_eq!(
            words("a && b || c; d | e & f |& g"),
            [["a"], ["b"], ["c"], ["d"], ["e"], ["f"], ["g"]]
        );
        assert_eq!(
            words("c'od'ex \\queue \"x y\""),
            [["codex", "queue", "x y"]]
        );
        assert_eq!(
            words("cat $HOME/a \"${HOME}/b\" ~/c ~"),
            [["cat", "/home/u/a", "/home/u/b", "/home/u/c", "/home/u"]]
        );
        assert_eq!(
            words("ls 2>&1 >out 2>>err <in"),
            [["ls", "out", "err", "in"]]
        );
        assert_eq!(words("echo '$X' a$ \"b$\""), [["echo", "$X", "a$", "b$"]]);
        assert_eq!(
            words("find . -exec rm {} \\;"),
            [["find", ".", "-exec", "rm", "{}", ";"]]
        );
        assert_eq!(words("cat <<< \"s t\""), [["cat", "s t"]]);
        assert_eq!(
            words("A=1 B=2 ls # comment\nwc"),
            vec![vec!["A=1", "B=2", "ls"], vec!["wc"]]
        );
        assert_eq!(words("ls \\\n -l"), [["ls", "-l"]]);
        assert_eq!(words("ls;"), [["ls"]]);
        assert_eq!(words("echo a>b"), [["echo", "a", "b"]]);
    }

    #[test]
    fn f1_glob_flag_marks_unquoted_wildcards_only() {
        let globs: Vec<bool> = match parse("ls *.pem '*.key'", "/h") {
            Parsed::Commands(cs) => cs.iter().flat_map(|c| &c.words).map(|w| w.glob).collect(),
            Parsed::Unparsed => Vec::new(),
        };
        assert_eq!(globs, [false, true, false]);
    }

    #[test]
    fn f1_redirection_targets_are_marked() {
        let flags: Vec<bool> = match parse("echo a > b 2>>c d <e", "/h") {
            Parsed::Commands(cs) => cs
                .iter()
                .flat_map(|c| &c.words)
                .map(|w| w.redirect)
                .collect(),
            Parsed::Unparsed => Vec::new(),
        };
        assert_eq!(flags, [false, false, true, true, false, true]);
    }

    // §12 F1.2: everything the guard cannot read is unparsed.
    #[test]
    fn f1_unreadable_forms_are_unparsed() {
        for t in [
            "echo $(codex queue)",
            "echo \"$(codex queue x y)\"",
            "echo \"a $((1+2))\"",
            "echo `id`",
            "diff <(a) <(b)",
            "tee >(cat)",
            "cat <<EOF\nhi\nEOF",
            "echo $PATH",
            "echo \"$USER\"",
            "echo ${HOME:-x}",
            "echo $1",
            "echo $'\\x63'",
            "echo $\"x\"",
            "echo {a,b}",
            "echo {1..3}",
            "if true; then ls; fi",
            "for x in a; do ls; done",
            "(cd /; ls)",
            "{ ls; }",
            "! ls",
            "echo 'open",
            "echo \"open",
            "ls |",
            "ls &&",
            "; ls",
            "ls ;; ls",
            "echo \\",
            "ls ~root",
            "f() { ls; }",
            "a=(1 2)",
        ] {
            assert_eq!(parse(t, "/h"), Parsed::Unparsed, "{t}");
        }
    }

    #[test]
    fn reserved_word_only_counts_in_command_position() {
        assert_eq!(words("echo if then"), [["echo", "if", "then"]]);
        assert_eq!(words("'if' x"), [["if", "x"]]);
    }
}
