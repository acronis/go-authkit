# go-authkit Extensions

This directory contains extensions to the core go-authkit library functionality. Extensions are organized into sub-packages based on their purpose and scope.

## Available Extensions

### acronisext

The `acronisext` package provides Acronis-specific extensions for JWT claims and token introspection results. 

Features include:
- Custom JWT claims extending the core `jwt.DefaultClaims`
- Standard structure for token introspection results
- Acronis-specific fields for authentication and authorization

See the [acronisext README](./acronisext/readme.md) for more details.

## Adding New Extensions

When adding new extensions to the go-authkit library, follow these guidelines:

1. Create a new subdirectory with a descriptive name (e.g., `vendorext` for vendor-specific extensions)
2. Include a `doc.go` file with package documentation
3. Include a README.md file with usage examples
4. Ensure comprehensive test coverage
5. Update the main README.md to reference the new extension

## Extension Design Principles

When designing extensions, follow these principles:

1. **Compatibility**: Extensions should enhance, not replace, core functionality
2. **Minimalism**: Only include what's necessary for the specific extension purpose
3. **Documentation**: Provide clear examples and use cases
4. **Test Coverage**: Ensure all extension code is well-tested
5. **Standardization**: Promote consistency across implementations
