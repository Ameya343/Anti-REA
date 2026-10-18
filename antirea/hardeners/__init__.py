"""Hardeners: non-destructive transforms that strip reverse-engineering signal.

Every hardener is semantics-preserving and writes to a NEW output tree; the
original is never modified. Hardeners refuse rather than guess: if a file does
not parse or a transform is unsafe, the file is copied verbatim and a note is
recorded.
"""
