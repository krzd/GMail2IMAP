# GMail2IMAP

This is a small wrapper that wraps the GMail API and exposes it as an IMAP API
using Python and Twisted. This allows to use IMAP clients where IMAP is
disabled, especially in some corporations.

During development I simply ran this locally with a fixed set of credentials,
ideally we would actually pass through Google credentials with the 2FA code and
authenticate directly using this as a proxy.

Not all features are implemented, currently it is mainly possible to retrieve
the list of emails and content in many cases. A lot of values are hardcoded
and any modification is not handled.

This may be developed in future if I still need it or otherwise is available
as a resource.
