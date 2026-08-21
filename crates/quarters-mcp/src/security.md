# Quarters security boundary

Quarters is state virtualization, not an OS security boundary. It preserves the
real UID/GID, filesystem authority, sudo identity, kernel, hardware, network,
login session, keychain and platform consent identity.

The server is a local stdio child of the MCP host. It opens no port and grants no
authority beyond the Unix account that launched it. Tool results may contain
local space paths and the captured default-shell path. They never contain
command arguments, credential values, other inherited environment values,
shell history or file contents from a space.

Stored control files are untrusted. Quarters validates ownership, file type,
permissions, link count, manifest size and space-name consistency without
following control-anchor symlinks. Activity is only the cooperative Quarters
lease; detached descendants remain unknown.

Agents should treat tool annotations as decision support, not authorization.
The MCP host must present meaningful user control for mutations.
