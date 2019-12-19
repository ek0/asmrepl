ASMREPL
====

Small utility useful for testing instructions side effects on Windows. Work using Vectored Exception Handler.

Usage
----
`asmrepl.exe [-x] [-y]`

- `-x`: show xmm registers with context
- `-y`: show ymm registers with context

REPL options
----
`!ctx`: Display the whole context again without modifying the current context
`!xmm`: Display xmm registers without modifying the current context
`!ymm`: Display ymm registers without modifying the current context