# No secret-shaped literals in the repository

No file holds a string that looks like an API key, a token, a password or a private key. This includes fake or example values. Test code builds such values at run time from parts, so no complete token appears in the source.
