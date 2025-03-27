# repo-pack: A Unix Tool for Flattening and Restoring Repositories

`repo-pack` flattens a directory (like a Git repository) into a single, portable text file and can restore it later. It preserves directory structure and file contents (text files only), including SHA-256 checksums for integrity verification.

## Features

*   **Flatten:** Pack a directory into a single text file.
*   **Restore:** Unpack the text file back into its original directory structure.
*   **Text-Only:** Automatically detects and skips binary files using `libmagic`.
*   **Integrity:** Stores SHA-256 hashes for each packed file and can verify them during extraction.
*   **Unix Philosophy:** Reads from directories, writes to standard output (packing), reads from files or standard input (unpacking), uses a simple text-based format.

## Installation

### Prerequisites

You need `gcc`, `make`, `libmagic-dev`, and `libssl-dev`. On Debian/Ubuntu 24.04:

```bash
sudo apt update
sudo apt install build-essential libmagic-dev libssl-dev