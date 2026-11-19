// Package caddysetup adds a rerouted instance's sites to a Caddy installation without ever
// replacing the operator's own configuration (rerouted init).
//
// rerouted's site blocks go in a file of their own, {Dir}/{name}.caddy, and its on-demand TLS
// ask in {Dir}/global/{name}.caddy. The Caddyfile only gains two import lines, inserted into
// the existing text after a backup: one at the top level for the sites, and one inside the
// global options block for the ask, which Caddy only accepts there. Everything is checked
// with caddy validate, and undone if that fails.
package caddysetup

import (
	"strings"
)

// token is one Caddyfile token and the line it starts on (0-based).
type token struct {
	text string
	line int
	// quoted tokens are never block braces, comments, or directives.
	quoted bool
}

// tokenize splits a Caddyfile into tokens the way Caddy's lexer does, closely enough to find
// blocks and imports: whitespace separates tokens, # at the start of a token comments out the
// rest of the line, "double" and `backtick` quotes make one token, and <<MARKER heredocs run
// to a line holding only MARKER.
func tokenize(src string) []token {
	var out []token
	lines := strings.Split(src, "\n")
	inHeredoc := ""
	quote := byte(0)
	var cur strings.Builder
	curLine := 0
	have := false
	flush := func() {
		if have {
			out = append(out, token{text: cur.String(), line: curLine, quoted: quote != 0})
		}
		cur.Reset()
		have = false
	}
	for ln, line := range lines {
		if inHeredoc != "" {
			if strings.TrimSpace(line) == inHeredoc {
				inHeredoc = ""
			}
			continue
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if quote != 0 {
				if c == '\\' && quote == '"' && i+1 < len(line) {
					cur.WriteByte(line[i+1])
					i++
					continue
				}
				if c == quote {
					flush()
					quote = 0
					continue
				}
				cur.WriteByte(c)
				continue
			}
			switch {
			case c == ' ' || c == '\t' || c == '\r':
				flush()
			case c == '#' && !have:
				i = len(line)
			case (c == '"' || c == '`') && !have:
				quote, have, curLine = c, true, ln
			case c == '<' && !have && strings.HasPrefix(line[i:], "<<") && len(line[i:]) > 2:
				inHeredoc = strings.TrimSpace(line[i+2:])
				out = append(out, token{text: "<<" + inHeredoc, line: ln})
				i = len(line)
			default:
				if !have {
					have, curLine = true, ln
				}
				cur.WriteByte(c)
			}
		}
		if quote == 0 {
			flush()
		} else {
			cur.WriteByte('\n') // a quoted token may span lines
		}
	}
	flush()
	return out
}

// layout is what Apply needs to know about a Caddyfile.
type layout struct {
	toks []token
	// global is the index in toks of the global options block's "{", or -1 if there's
	// none; globalEnd is its closing "}".
	global, globalEnd int
	// odd is set when the file can't be edited safely: unbalanced braces, or a global block
	// whose "{" shares its line with something else.
	odd string
}

func parse(src string) layout {
	l := layout{toks: tokenize(src), global: -1, globalEnd: -1}
	depth := 0
	for i, t := range l.toks {
		if t.quoted {
			continue
		}
		switch t.text {
		case "{":
			depth++
		case "}":
			depth--
			if depth < 0 {
				l.odd = "a closing brace without an opening one"
				return l
			}
			if depth == 0 && l.global >= 0 && l.globalEnd < 0 {
				l.globalEnd = i
			}
		}
		if i == 0 && t.text == "{" && !t.quoted {
			l.global = 0
			if len(l.toks) > 1 && l.toks[1].line == t.line {
				l.odd = "the global options block's { shares its line with other text"
				return l
			}
		}
	}
	if depth != 0 {
		l.odd = "unbalanced braces"
	}
	if l.global >= 0 && l.globalEnd < 0 {
		l.odd = "the global options block isn't closed"
	}
	return l
}

// hasImport reports whether an "import path" directive appears where wanted: at the top
// level (global false) or directly inside the global options block (global true).
func (l layout) hasImport(path string, global bool) bool {
	depth := 0
	for i, t := range l.toks {
		if t.quoted {
			continue
		}
		switch t.text {
		case "{":
			depth++
			continue
		case "}":
			depth--
			continue
		}
		if t.text != "import" || i+1 >= len(l.toks) || l.toks[i+1].text != path {
			continue
		}
		inGlobal := l.global >= 0 && i > l.global && i < l.globalEnd
		if global && inGlobal && depth == 1 || !global && !inGlobal && depth == 0 {
			return true
		}
	}
	return false
}

// onDemandAsk reports whether the global options block configures on_demand_tls, and the
// ask URL in it if it names one.
func (l layout) onDemandAsk() (found bool, ask string) {
	if l.global < 0 {
		return false, ""
	}
	return findAsk(l.toks[l.global+1 : l.globalEnd])
}

// findAsk looks for on_demand_tls in a run of tokens, and its ask.
func findAsk(toks []token) (found bool, ask string) {
	for i, t := range toks {
		if t.quoted {
			continue
		}
		if t.text == "on_demand_tls" {
			found = true
		}
		if found && t.text == "ask" && i+1 < len(toks) && ask == "" {
			ask = toks[i+1].text
		}
	}
	return found, ask
}

// generatedMarkers mark a Caddyfile something else writes: editing it would be undone the
// next time that runs.
var generatedMarkers = []string{"generated", "managed by", "do not edit", "don't edit", "auto-generated", "autogenerated"}

// IsGenerated reports whether a Caddyfile says it's generated or managed by a tool: in its
// header comment (the comment lines before anything else), or in a "# managed by" line
// anywhere.
func IsGenerated(src string) bool {
	header := true
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if !strings.HasPrefix(t, "#") {
			header = false
			continue
		}
		c := strings.ToLower(strings.TrimSpace(strings.TrimLeft(t, "#")))
		if strings.HasPrefix(c, "managed by") {
			return true
		}
		if header {
			for _, m := range generatedMarkers {
				if strings.Contains(c, m) {
					return true
				}
			}
		}
	}
	return false
}

// insertLines returns src with text inserted before line n (0-based; len(lines) appends).
func insertLines(src string, n int, text string) string {
	lines := strings.SplitAfter(src, "\n")
	if n >= len(lines) {
		if src != "" && !strings.HasSuffix(src, "\n") {
			src += "\n"
		}
		return src + text
	}
	var b strings.Builder
	for i, l := range lines {
		if i == n {
			b.WriteString(text)
		}
		b.WriteString(l)
	}
	return b.String()
}
