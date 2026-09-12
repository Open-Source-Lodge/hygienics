# Why

Development sessions on this repo can run through hygienics itself. The proxy redacts a secret-shaped string from the context of the model. When the model writes the file again, the placeholder replaces the value and the file is corrupt. This happened to `main_test.go`.

Build test tokens at run time. See `key` in `main_test.go`.
