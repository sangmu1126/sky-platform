"""Compatibility CLI for the packaged, trusted security collector."""

from interfaces.security_collector import collect_cycle, main, private_file

__all__ = ["collect_cycle", "main", "private_file"]

if __name__ == "__main__":
    main()
