# Security policy

## Reporting a vulnerability in KAFKA itself

Please report security problems in KAFKA (for example a way to bypass the scope checks,
make the tool send more than one request, leak cookie values, or inject content into a
report) **privately**:

1. On the repository page open **Security → Report a vulnerability** (GitHub private
   vulnerability reporting). The repository owner must have this feature enabled.
2. Include the KAFKA version (`kafka version`), your OS and Python version, and clear steps
   to reproduce. Do not include real credentials or data about systems you do not own.

Please do not open a public issue for a vulnerability until it has been fixed.

## Supported versions

Only the latest released version receives fixes.

## Responsible use

KAFKA is for websites you own or are explicitly authorized to assess. The maintainers do not
support or condone scanning systems without permission. Design details and known limitations
are in [docs/SECURITY.md](docs/SECURITY.md).
