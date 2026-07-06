# xxHash (vendored)

`xxhash.h` — the single-header, header-only distribution of
[xxHash](https://github.com/Cyan4973/xxHash), used for XXH3-64 query
fingerprints in `src/norm/` (Р22, STAGE4.md task 4.1).

- **Version:** v0.8.2 (`XXH_VERSION` 0.8.2)
- **Source:** https://github.com/Cyan4973/xxHash/blob/v0.8.2/xxhash.h
- **License:** BSD 2-Clause — see `LICENSE`.

`src/norm/norm_sql.c` is the only consumer; it defines `XXH_INLINE_ALL`
before the include, so the implementation is emitted as `static` functions in
that one translation unit (no separate `xxhash.c`, no exported symbols). The
directory is added as a **SYSTEM** include so the project's `-Werror` does not
police third-party code.

Update by replacing `xxhash.h` (and `LICENSE`) with a newer tagged release and
bumping the version above.
