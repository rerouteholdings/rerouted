package main

import (
	"fmt"
	"os"
	"strings"
)

// subWords are the fixed words some commands take.
var subWords = map[string][]string{
	"config":       {"check"},
	"auto-updates": {"on", "off", "status"},
	"completion":   {"bash", "zsh", "fish"},
	"status":       {"--json"},
	"checkup":      {"--peer", "--handle"},
	"restore":      {"--force"},
	"init": {"--name", "--handles", "--listen", "--data-dir", "--registration", "--env",
		"--yes", "--no-caddy", "--caddy-only", "--auto-updates", "--start"},
}

func commandNames() []string {
	var names []string
	for _, c := range commands {
		names = append(names, c.name)
	}
	return names
}

func runCompletion(_ *globals, args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: rerouted completion bash|zsh|fish")
		return 2
	}
	switch args[1] {
	case "bash":
		fmt.Print(bashCompletion())
	case "zsh":
		fmt.Print(zshCompletion())
	case "fish":
		fmt.Print(fishCompletion())
	default:
		fmt.Fprintln(os.Stderr, "usage: rerouted completion bash|zsh|fish")
		return 2
	}
	return 0
}

func bashCompletion() string {
	var cases strings.Builder
	for _, c := range commands {
		if w, ok := subWords[c.name]; ok {
			fmt.Fprintf(&cases, "\t\t%s) COMPREPLY=($(compgen -W %q -- \"$cur\")) ;;\n", c.name, strings.Join(w, " "))
		}
	}
	return `# bash completion for rerouted. Install: rerouted completion bash > /etc/bash_completion.d/rerouted
_rerouted() {
	local cur prev cmd i
	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	case "$prev" in
		-env|--env|--data-dir) COMPREPLY=($(compgen -f -- "$cur")); return ;;
	esac
	cmd=""
	for ((i = 1; i < COMP_CWORD; i++)); do
		case "${COMP_WORDS[i]}" in
			-env|--env) ((i++)) ;;
			-*) ;;
			*) cmd="${COMP_WORDS[i]}"; break ;;
		esac
	done
	if [ -z "$cmd" ]; then
		COMPREPLY=($(compgen -W "-env ` + strings.Join(commandNames(), " ") + `" -- "$cur"))
		return
	fi
	case "$cmd" in
` + cases.String() + `		backup) COMPREPLY=($(compgen -d -- "$cur")) ;;
	esac
	case "$cmd" in
		restore) COMPREPLY+=($(compgen -f -- "$cur")) ;;
	esac
}
complete -F _rerouted rerouted
`
}

func zshCompletion() string {
	var cmds strings.Builder
	for _, c := range commands {
		fmt.Fprintf(&cmds, "\t\t'%s:%s'\n", c.name, strings.ReplaceAll(c.summary, "'", "'\\''"))
	}
	var cases strings.Builder
	for _, c := range commands {
		if w, ok := subWords[c.name]; ok {
			fmt.Fprintf(&cases, "\t\t%s) compadd -- %s ;;\n", c.name, strings.Join(w, " "))
		}
	}
	return `#compdef rerouted
# zsh completion for rerouted. Install: rerouted completion zsh > "${fpath[1]}/_rerouted"
_rerouted() {
	local -a cmds
	cmds=(
` + cmds.String() + `	)
	local i cmd=""
	for ((i = 2; i < CURRENT; i++)); do
		case "${words[i]}" in
			-env|--env) ((i++)) ;;
			-*) ;;
			*) cmd="${words[i]}"; break ;;
		esac
	done
	case "${words[CURRENT-1]}" in
		-env|--env|--data-dir) _files; return ;;
	esac
	if [[ -z "$cmd" ]]; then
		_describe 'command' cmds
		compadd -- -env
		return
	fi
	case "$cmd" in
` + cases.String() + `		backup) _files -/ ;;
	esac
	case "$cmd" in
		restore) _files ;;
	esac
}
_rerouted "$@"
`
}

func fishCompletion() string {
	var b strings.Builder
	b.WriteString("# fish completion for rerouted. Install: rerouted completion fish > ~/.config/fish/completions/rerouted.fish\n")
	all := strings.Join(commandNames(), " ")
	b.WriteString("complete -c rerouted -f\n")
	b.WriteString("complete -c rerouted -o env -r -F -d 'settings file'\n")
	for _, c := range commands {
		fmt.Fprintf(&b, "complete -c rerouted -n 'not __fish_seen_subcommand_from %s' -a %s -d '%s'\n",
			all, c.name, strings.ReplaceAll(c.summary, "'", "\\'"))
	}
	for _, c := range commands {
		if w, ok := subWords[c.name]; ok {
			fmt.Fprintf(&b, "complete -c rerouted -n '__fish_seen_subcommand_from %s' -a '%s'\n", c.name, strings.Join(w, " "))
		}
	}
	b.WriteString("complete -c rerouted -n '__fish_seen_subcommand_from restore backup' -F\n")
	return b.String()
}
