# JNetRuntime BPF Compiler

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Java Version](https://img.shields.io/badge/java-%3E%3D%208-orange.svg)]()

A multi-dialect Berkeley Packet Filter (BPF) compiler that translates various filter expression languages into BPF bytecode, compatible with both the JNetRuntime BPF VM and kernel BPF interpreter.

## Overview

JNetRuntime BPF Compiler provides a flexible compilation framework that supports multiple filter expression dialects through a unified interface. The compiler transforms high-level filter expressions into optimized BPF bytecode using a sophisticated pipeline of lexical analysis, parsing, and code generation.

## Supported Dialects

### 1. PCAP/TCPDump Filter Expressions
```java
// TCPDump style filtering
BpfCompiler compiler = new PcapCompiler();
byte[] bytecode = compiler.compile("tcp port 80 and not broadcast");
```

Example expressions:
```
tcp port 80
ip host 192.168.1.1
ether src 00:11:22:33:44:55
ip6 and tcp port 443
```

### 2. Wireshark Display Filters
```java
// Wireshark style filtering
BpfCompiler compiler = new WiresharkCompiler();
byte[] bytecode = compiler.compile("tcp.port == 80 && ip.addr != 10.0.0.0/8");
```

Example expressions:
```
http.request.method == "GET"
tcp.flags.syn == 1
ip.src == 192.168.0.0/16
http.host contains "example.com"
```

### 3. Napatech NTPL Filters
```java
// NTPL style filtering
BpfCompiler compiler = new NtplCompiler();
byte[] bytecode = compiler.compile("Layer3Protocol == IPv4 AND TCP[DstPort] == 80");
```

Example expressions:
```
Layer4Protocol == TCP
IPv4[SrcAddr] == 192.168.1.1
TCP[DstPort] == 443
VLAN[Id] == 100
```

## Architecture

### Compilation Pipeline

```
Filter Expression
       ↓
[Lexical Analyzer]
       ↓
 Token Stream
       ↓
   [Parser]
       ↓
IR Representation
       ↓
[Code Generator]
       ↓
 BPF Bytecode
```

### Key Components

1. **Lexical Analyzer**
   - Breaks input string into tokens
   - Handles dialect-specific lexical rules
   - Provides token stream to parser

2. **Parser**
   - Builds Abstract Syntax Tree (AST)
   - Performs semantic analysis
   - Generates Intermediate Representation (IR)

3. **Code Generator**
   - Converts IR to BPF instructions
   - Performs optimizations
   - Generates final bytecode

## Installation

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.jnetruntime</groupId>
    <artifactId>jnetruntime-bpf-compiler</artifactId>
    <version>${latest.version}</version>
</dependency>
```

## Usage

### Basic Compilation

```java
// Create compiler instance for desired dialect
BpfCompiler compiler = new PcapCompiler();  // or WiresharkCompiler or NtplCompiler

// Compile expression to BPF bytecode
try {
    byte[] bytecode = compiler.compile("tcp port 80");
    
    // Use with JNetRuntime BPF VM
    BPFProgram program = BPFProgram.load(bytecode);
    
    // Or with kernel BPF
    int fd = KernelBPF.load(bytecode);
} catch (CompilerException e) {
    // Handle compilation errors
}
```

### Dialect Selection

```java
// Factory method for dialect selection
BpfCompiler compiler = BpfCompiler.forDialect(FilterDialect.PCAP);
BpfCompiler compiler = BpfCompiler.forDialect(FilterDialect.WIRESHARK);
BpfCompiler compiler = BpfCompiler.forDialect(FilterDialect.NTPL);
```

### Compilation Options

```java
CompilerOptions options = CompilerOptions.builder()
    .optimizationLevel(OptimizationLevel.AGGRESSIVE)
    .debug(true)
    .build();

BpfCompiler compiler = new PcapCompiler(options);
byte[] bytecode = compiler.compile("complex expression");
```

### Error Handling

```java
try {
    byte[] bytecode = compiler.compile("invalid expression");
} catch (SyntaxException e) {
    System.err.println("Syntax error: " + e.getMessage());
    System.err.println("At position: " + e.getPosition());
} catch (SemanticException e) {
    System.err.println("Semantic error: " + e.getMessage());
} catch (CompilerException e) {
    System.err.println("Compilation failed: " + e.getMessage());
}
```

## Extending the Compiler

### Adding a New Dialect

```java
public class CustomDialectCompiler implements BpfCompiler {
    @Override
    public byte[] compile(String expression) throws CompilerException {
        // 1. Implement lexical analysis
        TokenStream tokens = lexicalAnalyze(expression);
        
        // 2. Implement parsing
        IR ir = parse(tokens);
        
        // 3. Generate code
        return generateCode(ir);
    }
}
```

### Custom Optimizations

```java
public class CustomOptimizer implements IROptimizer {
    @Override
    public IR optimize(IR input) {
        // Implement optimization logic
        return optimizedIR;
    }
}
```

## Performance Considerations

- Compiled expressions are cached for reuse
- Optimization levels control compilation time vs runtime performance
- Runtime performance matches native kernel BPF
- Memory efficient IR representation

## Building from Source

```bash
git clone https://github.com/jnetruntime/jnetruntime-bpf-compiler.git
cd jnetruntime-bpf-compiler
mvn clean install
```

## Contributing

We welcome contributions! Areas of interest:

- New dialect implementations
- Optimization improvements
- Bug fixes and testing
- Documentation enhancements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Integration

### With JNetRuntime BPF VM

```java
// Compile and execute
BpfCompiler compiler = new PcapCompiler();
byte[] bytecode = compiler.compile("tcp port 80");

BPFProgram program = BPFProgram.load(bytecode);
boolean matches = program.execute(packet);
```

### With Kernel BPF

```java
// Compile and load to kernel
BpfCompiler compiler = new PcapCompiler();
byte[] bytecode = compiler.compile("tcp port 80");

int fd = KernelBPF.load(bytecode);
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [jnetruntime-bpf-vm](link-to-vm) - BPF Virtual Machine implementation
- [jnetruntime-core](link-to-core) - Core networking utilities

## References

- [TCPDump Filter Expression Syntax](link-to-tcpdump)
- [Wireshark Display Filter Reference](link-to-wireshark)
- [Napatech NTPL Reference](link-to-ntpl)
- [BPF Instruction Set Architecture](link-to-bpf)

## Support

- Issues: [GitHub Issues](link-to-issues)
- Discussions: [GitHub Discussions](link-to-discussions)
- Email: [support@jnetruntime.org](mailto:support@jnetruntime.org)
