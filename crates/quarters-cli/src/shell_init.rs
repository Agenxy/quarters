//! Shell integration emitted as code from the trusted Quarters binary.

use crate::cli::ShellKind;

const ZSH_INIT: &str = r#"# Quarters shell integration v1
if [[ -o interactive && -n ${QUARTERS_PROMPT_PREFIX:-} && -z ${_QUARTERS_PROMPT_INSTALLED:-} ]]; then
  typeset -g _QUARTERS_PROMPT_INSTALLED=1
  if [[ -n ${NO_COLOR:-} ]]; then
    PROMPT="${QUARTERS_PROMPT_PREFIX}${PROMPT:-%~ %# }"
  else
    PROMPT="%F{45}${QUARTERS_PROMPT_PREFIX}%f${PROMPT:-%~ %# }"
  fi
fi
"#;

const BASH_INIT: &str = r#"# Quarters shell integration v1
if [[ $- == *i* && -n ${QUARTERS_PROMPT_PREFIX:-} && -z ${_QUARTERS_PROMPT_INSTALLED:-} ]]; then
  _QUARTERS_PROMPT_INSTALLED=1
  if [[ -n ${NO_COLOR:-} ]]; then
    PS1="${QUARTERS_PROMPT_PREFIX}${PS1:-\w \\$ }"
  else
    PS1="\[\033[38;5;45m\]${QUARTERS_PROMPT_PREFIX}\[\033[0m\]${PS1:-\w \\$ }"
  fi
fi
"#;

/// Return the integration code for one supported interactive shell.
pub(crate) const fn script(shell: ShellKind) -> &'static str {
    match shell {
        ShellKind::Zsh => ZSH_INIT,
        ShellKind::Bash => BASH_INIT,
    }
}

#[cfg(test)]
mod tests {
    use super::{BASH_INIT, ZSH_INIT};

    #[test]
    fn snippets_use_only_the_validated_prompt_prefix() {
        for snippet in [ZSH_INIT, BASH_INIT] {
            assert!(snippet.contains("QUARTERS_PROMPT_PREFIX"));
            for unsafe_value in ["QUARTERS_ROOT", "QUARTERS_SPACE_ROOT", "QUARTERS_SPACE_HOME"] {
                assert!(!snippet.contains(unsafe_value));
            }
        }
    }
}
