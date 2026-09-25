"""
conftest.py — pytest configuration for the IPsec simulator test suite.

Adds the backend directory to sys.path so tests can import app modules
without installation.
"""

import sys
import os

# Add backend directory to path so `from app.xxx import yyy` works
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))
