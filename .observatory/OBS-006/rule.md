# Secret sources are opt-in

The proxy reads secrets only from the secrets file by default. Each other source needs an explicit action from the user: a flag, a config value, or a subcommand. No change adds a source that the proxy reads without such an action.
