# Contributing to EFSF

Thank you for your interest in contributing to the Ephemeral-First Security Framework! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful of differing viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what is best for the community and the project
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs actual behavior
- **Environment details** (OS, Python version, Redis version, etc.)
- **Relevant logs or error messages**

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:

- **Clear title** describing the enhancement
- **Detailed description** of the proposed functionality
- **Use case** explaining why this would be useful
- **Possible implementation** approach (if you have ideas)

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Write tests** for any new functionality
3. **Ensure tests pass** by running `pytest`
4. **Update documentation** if needed
5. **Follow the code style** (we use `black` for formatting, `mypy` for type checking)
6. **Write clear commit messages**

#### Pull Request Process

1. Update the README.md or relevant docs with details of changes
2. Add tests that cover your changes
3. Ensure CI passes
4. Request review from maintainers
5. Squash commits before merging

## Development Setup

### Prerequisites

- Python 3.9+
- Redis (for integration tests)
- Docker (optional, for containerized testing)

### Setting Up Your Environment

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/ephemeral-first-security-framework.git
cd ephemeral-first-security-framework

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install development dependencies
cd sdk/python
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
black --check efsf/
mypy efsf/
```

### Running Redis for Tests

```bash
# Using Docker
docker run -d -p 6379:6379 redis:7-alpine

# Or install locally (macOS)
brew install redis
redis-server
```

## Code Style

### Python

- Use `black` for code formatting
- Use `mypy` for type checking
- Use `isort` for import sorting
- Write docstrings for all public functions/classes
- Aim for >90% test coverage

```python
# Example of expected style
from typing import Optional
from datetime import timedelta

def create_ephemeral_record(
    data: dict,
    ttl: timedelta,
    classification: str = "TRANSIENT"
) -> EphemeralRecord:
    """
    Create a new ephemeral record with the specified TTL.

    Args:
        data: The data to store
        ttl: Time-to-live duration
        classification: Data classification level

    Returns:
        EphemeralRecord with assigned ID and metadata

    Raises:
        ValidationError: If data or TTL is invalid
    """
    ...
```

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(store): add DynamoDB backend support`
- `fix(crypto): resolve key rotation race condition`
- `docs(readme): update installation instructions`

## Architecture Guidelines

When contributing new features, consider:

### 1. Ephemerality First
Every feature should support or enhance the ephemeral-first paradigm. Ask yourself:
- Does this feature minimize data retention?
- Can destruction be verified?
- Is the TTL enforced, not just suggested?

### 2. Backend Agnostic
Core interfaces should work across different storage backends:
- Abstract storage operations
- Don't assume Redis-specific features in core logic
- Use adapter patterns for backend-specific code

### 3. Attestation Built-In
All destructive operations should support attestation:
- Generate destruction certificates
- Maintain audit trails
- Support compliance reporting

### 4. Security by Default
- Encryption should be mandatory, not optional
- Fail secure (deny) rather than fail open (allow)
- Minimal dependencies to reduce attack surface

## Areas We Need Help

### High Priority
- [ ] PostgreSQL backend implementation
- [ ] DynamoDB backend implementation
- [ ] Go SDK development
- [ ] TypeScript SDK development
- [ ] Security audit of cryptographic operations

### Medium Priority
- [ ] Kubernetes operator
- [ ] Terraform provider
- [ ] Performance benchmarks
- [ ] Integration examples (FastAPI, Django, Flask)

### Documentation
- [ ] Architecture deep-dive guides
- [ ] Video tutorials
- [ ] Compliance mapping guides
- [ ] Migration guides from other approaches

## Questions?

- Open a [Issue/Discussion](https://github.com/akshat666/ephemeral-first-security-framework/issues) for general questions
- Join our community (links coming soon)
- Email maintainers for security issues (see SECURITY.md)

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for helping make EFSF better! 🛡️
