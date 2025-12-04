# AI Vulnerability Scanner

An AI-powered static application security testing (SAST) tool that leverages Large Language Models (LLMs) via Ollama to automatically scan source code for security vulnerabilities.

## Overview

This tool uses AI models to analyze code files and identify potential security vulnerabilities, providing detailed descriptions, severity ratings, and remediation recommendations. It generates comprehensive markdown reports for review by security teams and developers.

## Features

- 🤖 **AI-Powered Analysis**: Utilizes LLMs through Ollama for intelligent vulnerability detection
- 🔍 **Multi-Language Support**: Scans C#, JavaScript, Python, and TypeScript files
- 📊 **Severity Classification**: Categorizes vulnerabilities as HIGH, MEDIUM, or LOW
- 📝 **Detailed Reports**: Generates markdown reports with descriptions and fix recommendations
- 🚀 **Batch Scanning**: Recursively scans entire project directories
- ⚡ **Smart Filtering**: Automatically skips common build/dependency directories
- 🎯 **Vulnerability Type Detection**: Identifies common security issues (SQL injection, XSS, CSRF, etc.)

## Requirements

### System Requirements
- Python 3.7+
- [Ollama](https://ollama.ai/) installed and running
- Compatible LLM model downloaded via Ollama

### Python Dependencies
```bash
pip install ollama
```

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd AiSastTool
   ```

2. **Install dependencies**
   ```bash
   pip install ollama
   ```

3. **Install and configure Ollama**
   - Download Ollama from https://ollama.ai/
   - Install a suitable model:
     ```bash
     ollama pull deepseek-r1:32b
     # or
     ollama pull codellama:34b
     ```

4. **Start Ollama service**
   ```bash
   ollama serve
   ```

## Configuration

Edit the configuration variables in `ai_analyser.py` (lines 270-278):

```python
OLLAMA_HOST = "http://localhost:11434"  # Ollama server address
OLLAMA_MODEL = "deepseek-r1:32b"        # Model to use
project_path = "/path/to/your/project"  # Target project directory
```

### Supported Models
- `deepseek-r1:32b` (default)
- `codellama:34b`
- Any other code-focused Ollama model

### Configurable Parameters
- **File Extensions**: Modify the `extensions` parameter in `scan_directory()` (default: `.cs`, `.js`, `.py`, `.ts`)
- **Skip Directories**: Update the `skip_dirs` set (line 196) to exclude additional directories
- **File Size Limit**: Adjust character limit for file content (default: 3000 chars, line 16)
- **Temperature**: Control model creativity (default: 0.3, line 48)
- **Response Length**: Adjust `num_predict` for longer/shorter responses (default: 1024, line 49)

## Usage

### Basic Usage

```bash
python ai_analyser.py
```

### Programmatic Usage

```python
from ai_analyser import VulnerabilityScanner

# Initialize scanner
scanner = VulnerabilityScanner(
    model_name="deepseek-r1:32b",
    host="http://localhost:11434"
)

# Scan a directory
scanner.scan_directory(
    "/path/to/project",
    extensions=['.cs', '.js', '.py', '.ts']
)

# Generate report
scanner.generate_report("vulnerability_report.md")
```

### Scan Single File

```python
scanner = VulnerabilityScanner()

with open("myfile.py", "r") as f:
    content = f.read()

scanner.scan_file("myfile.py", content)
scanner.generate_report()
```

## Output

The scanner generates a markdown report (`vulnerability_report.md`) with:

- **Summary Statistics**: Total issues and breakdown by severity
- **Detailed Findings**: For each vulnerability:
  - Severity level (🔴 HIGH, 🟡 MEDIUM, 🟢 LOW)
  - Vulnerability type (e.g., SQL Injection, XSS, Hard-coded Credentials)
  - Affected file path
  - Complete description of the issue
  - Remediation recommendations

### Example Report Structure

```markdown
# Vulnerability Scan Report

**Total Issues Found:** 5

- 🔴 **HIGH**: 2
- 🟡 **MEDIUM**: 2
- 🟢 **LOW**: 1

---

## 🔴 Issue #1: SQL Injection

**Severity:** HIGH

**File:** `src/database/query.py`

**Description:**
[Detailed AI-generated description of the vulnerability]

**Recommendation:** [Specific fix recommendations]

---
```

## Detected Vulnerability Types

The scanner can identify various security issues including:

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Authentication/Authorization Issues
- Hard-coded Credentials
- Encryption Issues
- SSL/TLS Problems
- Input Validation Issues
- Path Traversal
- Command Injection
- Insecure Deserialization
- XML External Entity (XXE)

## Excluded Directories

The following directories are automatically skipped during scanning:

- `node_modules/`
- `bin/`
- `obj/`
- `.git/`
- `dist/`
- `build/`
- `__pycache__/`
- `.vs/`

## Limitations

- **File Size**: Files larger than 3000 characters are truncated to avoid overwhelming the model
- **False Positives**: AI analysis may produce false positives; manual review is recommended
- **Model Dependency**: Accuracy depends on the capabilities of the selected LLM
- **Performance**: Scanning speed depends on Ollama server performance and model size
- **Network**: Requires network access to Ollama server (local or remote)

## Performance Considerations

- **Large Projects**: Scanning time increases with project size
- **Remote Ollama**: Network latency affects scan duration
- **Model Size**: Larger models (e.g., 34b) provide better accuracy but slower performance
- **Parallel Processing**: Current implementation scans files sequentially

## Troubleshooting

### Common Issues

**Ollama connection error**
```
Solution: Ensure Ollama is running: ollama serve
```

**Model not found**
```
Solution: Download the model: ollama pull deepseek-r1:32b
```

**Empty response**
```
Solution: Increase num_predict parameter for longer responses
```

**Timeout errors**
```
Solution: Use a smaller model or increase timeout settings
```

## Best Practices

1. **Review Results**: Always manually review AI-generated findings
2. **Supplement Tools**: Use alongside traditional SAST tools
3. **Keep Updated**: Regularly update Ollama and models
4. **Tune Settings**: Adjust temperature and response length for your needs
5. **Test Coverage**: Ensure all critical files are scanned

## Contributing

Contributions are welcome! Areas for improvement:

- Additional language support
- Parallel file processing
- Custom rule definitions
- Integration with CI/CD pipelines
- Enhanced parsing of AI responses
- Support for additional LLM providers

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.

## Credits

Built using:
- [Ollama](https://ollama.ai/) - Local LLM runtime
- Various open-source LLM models

## Support

For issues or questions:
- Open an issue in the repository
- Refer to [Ollama documentation](https://github.com/ollama/ollama)

---

**Note**: This tool uses AI for vulnerability detection. Results should be validated by security professionals before taking action. AI analysis may not catch all vulnerabilities and may produce false positives.
