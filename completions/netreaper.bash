# NETREAPER bash completion
#
# THE WORD LISTS BELOW ARE CHECKED AGAINST THE CLI. tests/unit/
# test_completion_matches_the_cli.py walks the Typer app and fails if this file
# offers a command that does not exist or omits one that does.
#
# It needed that. Before this rewrite the list was written for v10 and never
# touched again: it offered nine commands the CLI does not have (menu, wizard,
# discover, install, session, update, logs, export, help) and omitted nine it
# does, including `engage`, which is how authorisation is established and
# therefore the one command nothing else works without.

_netreaper() {
    local cur prev
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion || return
    else
        # No bash-completion package present. Fall back to COMP_WORDS instead
        # of returning: the previous version's bare `_init_completion || return`
        # meant that on any box without bash-completion installed, pressing Tab
        # did nothing at all and gave no clue why.
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
    fi

    local commands="can config creds engage osint plugin portscan resources scan status tui web wifi"
    local global_opts="--help --install-completion --show-completion --version"

    local can_cmds="dump interfaces"
    local creds_cmds="attack"
    local engage_cmds="end start status"
    local osint_cmds="subdomains"
    local plugin_cmds="list"
    local resources_cmds="list show"
    local web_cmds="auto dirs fingerprint"
    local wifi_cmds="arpspoof auto crack downgrade enterprise eviltwin handshake hidden mac-clone mac-random monitor plan pmkid scan tear wep wpa3 wps"

    local words_to_offer=""
    case "${prev}" in
        netreaper)   words_to_offer="${commands} ${global_opts}" ;;
        can)         words_to_offer="${can_cmds}" ;;
        creds)       words_to_offer="${creds_cmds}" ;;
        engage)      words_to_offer="${engage_cmds}" ;;
        osint)       words_to_offer="${osint_cmds}" ;;
        plugin)      words_to_offer="${plugin_cmds}" ;;
        resources)   words_to_offer="${resources_cmds}" ;;
        web)         words_to_offer="${web_cmds}" ;;
        wifi)        words_to_offer="${wifi_cmds}" ;;
        *)           words_to_offer="${commands}" ;;
    esac

    # mapfile rather than COMPREPLY=($(...)): the array form word-splits and
    # glob-expands each candidate, so a completion containing a space or a
    # bracket comes back mangled.
    mapfile -t COMPREPLY < <(compgen -W "${words_to_offer}" -- "${cur}")
}

complete -F _netreaper netreaper
