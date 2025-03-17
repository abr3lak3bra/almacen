# Almacen

A secure storage manager for private keys

## Features

- **Secure Encryption**: Uses ChaCha20-Poly1305 for data encryption
- **Memory Protection**: Implements memory locking for sensitive data
- **SQLite Storage**: Secure local database storage
- **Password Protection**: Master password required for access
- **Import/Export**: Support for CSV import and export
- **Command Interface**: Simple command-line interface

## Commands

- `a [name] [key]` - Add new entry
- `v [start] [end]` - View entries (paginated)
- `r [name]` - Remove entry
- `i` - Import from CSV
- `e` - Export to CSV
- `q` - Quit

## Security Features

- Memory protection for sensitive data
- Secure key derivation
- Protected file storage
- Input validation and sanitization
- Encrypted database entries
- Secure password hashing

## Technical Details

- **Database**: SQLite with Diesel ORM
- **Encryption**: Ring crypto library (ChaCha20-Poly1305)
- **Password Hashing**: Ring crypto library (PBKDF2_HMAC_SHA256)
- **Maximum name length**: 9 characters
- **Allowed characters**: Alphanumeric and underscores

## Security Notes

- Master password is required for access
- Data is encrypted at rest
- Keys are protected in memory
- Protected file operations