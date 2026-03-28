# Precomputed tables for sparse keys

This directory contains precomputed Markdown tables for sparse-key parameter sets.
Each table gives the largest `logq` found for a fixed target security level.

## Common conventions

All tables in this directory use:

- error standard deviation `sigma = 3.2`
- power-of-two ring dimension `n = 2^logn`
- sparse ternary secret with Hamming weight `h`
- ciphertext modulus `q = 2^logq`

## Files

- [`128bits_security.md`](128bits_security.md)
  Largest `logq` values targeting at least `128` bits of security.
- [`192bits_security.md`](192bits_security.md)
  Largest `logq` values targeting at least `192` bits of security.
- [`256bits_security.md`](256bits_security.md)
  Largest `logq` values targeting at least `256` bits of security.

## Table layout

Each table is organized as follows:

- rows: `logn`
- columns: secret Hamming weight `h`
- cell value: the largest admissible `logq`

For example, a cell containing `19` means that the search found `q = 2^19` as the largest modulus meeting the target security level for that `(logn, h)` pair.

## Special cell values

- an integer such as `19`
  A concrete `logq` value was found.
- `--`
  No admissible `logq` was found in the searched range for that cell.
- an empty cell
  The entry has not been filled yet.

