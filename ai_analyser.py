import ollama
import os
import json
from pathlib import Path

class VulnerabilityScanner:
    def __init__(self, model_name="deepseek-r1:32b", host="http://localhost:11434"):
        self.model = model_name
        self.vulnerabilities = []
        self.client = ollama.Client(host=host)
    
    def scan_file(self, file_path, file_content):
        """Scan a single file for vulnerabilities"""
        
        # Limit file size to avoid overwhelming the model
        if len(file_content) > 3000:
            file_content = file_content[:3000] + "\n... (file truncated)"
        
        prompt = f"""You are a security expert. Analyze this code for vulnerabilities.

File: {file_path}

Code:
```
{file_content}
```

List any security vulnerabilities you find. For each vulnerability provide a COMPLETE analysis including:
- Severity (HIGH, MEDIUM, or LOW)
- Type of vulnerability
- Full description of the issue
- Complete recommendation to fix it

Be thorough and complete in your explanation. Do not cut off mid-sentence.

If no vulnerabilities are found, respond with only: "NO VULNERABILITIES FOUND"
"""
        
        result = None
        
        try:
            print(f"  Calling model for {os.path.basename(file_path)}...")
            
            response = self.client.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}],
                options={
                    'temperature': 0.3,
                    'num_predict': 1024  # Allow longer responses (increase if needed)
                }
            )
            
            # Safely extract the result
            if response and 'message' in response and 'content' in response['message']:
                result = response['message']['content']
                print(f"  ✓ Got response ({len(result)} chars)")
            else:
                print(f"  ✗ Unexpected response structure")
                return {"status": "error"}
            
            # Parse the response
            if result and "NO VULNERABILITIES" not in result.upper():
                # Try to parse structured findings
                findings = self.parse_vulnerability_response(result, file_path)
                
                if findings:
                    for finding in findings:
                        self.vulnerabilities.append(finding)
                    print(f"  ⚠ {len(findings)} vulnerability(ies) detected")
                else:
                    # Fallback: treat entire response as one vulnerability
                    vuln = {
                        'file': file_path,
                        'severity': self.extract_severity(result),
                        'type': 'Potential Security Issue',
                        'description': result.strip(),  # Full response, no truncation
                        'recommendation': 'See description for details'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"  ⚠ Vulnerability detected")
            else:
                print(f"  ✓ No issues found")
            
            return {"status": "success"}
            
        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
            if result:
                print(f"  Response was: {result[:100]}")
            return {"status": "error", "message": str(e)}
    
    def parse_vulnerability_response(self, response_text, file_path):
        """Try to parse multiple vulnerabilities from response"""
        findings = []
        
        # Split by common delimiters that indicate separate vulnerabilities
        # Look for numbered lists or clear separators
        sections = []
        
        # Try to split by numbered items (1., 2., etc.)
        import re
        numbered_pattern = r'\n\s*(\d+)\.\s+'
        parts = re.split(numbered_pattern, response_text)
        
        if len(parts) > 2:  # We found numbered items
            #parts will be ['intro', '1', 'content1', '2', 'content2', ...]
            for i in range(1, len(parts), 2):
                if i + 1 < len(parts):
                    sections.append(parts[i + 1].strip())
        else:
            # No clear structure, treat as single finding
            sections = [response_text.strip()]
        
        # Parse each section
        for section in sections:
            if len(section) < 20:  # Skip very short sections
                continue
                
            vuln = {
                'file': file_path,
                'severity': self.extract_severity(section),
                'type': self.extract_vulnerability_type(section),
                'description': section,  # Full section text
                'recommendation': self.extract_recommendation(section)
            }
            findings.append(vuln)
        
        return findings
    
    def extract_vulnerability_type(self, text):
        """Try to extract vulnerability type from text"""
        text_lower = text.lower()
        
        # Common vulnerability types
        types = {
            'sql injection': 'SQL Injection',
            'xss': 'Cross-Site Scripting (XSS)',
            'cross-site scripting': 'Cross-Site Scripting (XSS)',
            'csrf': 'Cross-Site Request Forgery (CSRF)',
            'authentication': 'Authentication Issue',
            'authorization': 'Authorization Issue',
            'hardcoded': 'Hard-coded Credentials',
            'hard-coded': 'Hard-coded Credentials',
            'password': 'Password Security',
            'encryption': 'Encryption Issue',
            'ssl': 'SSL/TLS Issue',
            'tls': 'SSL/TLS Issue',
            'certificate': 'Certificate Validation',
            'input validation': 'Input Validation',
            'path traversal': 'Path Traversal',
            'command injection': 'Command Injection',
            'deserialization': 'Insecure Deserialization',
            'xxe': 'XML External Entity (XXE)',
        }
        
        for pattern, vuln_type in types.items():
            if pattern in text_lower:
                return vuln_type
        
        return 'Security Issue'
    
    def extract_recommendation(self, text):
        """Try to extract recommendation from text"""
        text_lower = text.lower()
        
        # Look for recommendation keywords
        rec_markers = ['recommendation:', 'fix:', 'solution:', 'mitigation:', 'remediation:']
        
        for marker in rec_markers:
            if marker in text_lower:
                idx = text_lower.index(marker)
                recommendation = text[idx + len(marker):].strip()
                # Take up to next section or end
                next_section = recommendation.find('\n\n')
                if next_section > 0:
                    recommendation = recommendation[:next_section]
                return recommendation[:500]  # Limit to 500 chars
        
        return 'Review and remediate the identified security issue'
    
    def extract_severity(self, text):
        """Extract severity from text response"""
        text_lower = text.lower()
        if 'high' in text_lower or 'critical' in text_lower or 'severe' in text_lower:
            return 'HIGH'
        elif 'medium' in text_lower or 'moderate' in text_lower:
            return 'MEDIUM'
        elif 'low' in text_lower or 'minor' in text_lower:
            return 'LOW'
        return 'MEDIUM'
    
    def scan_directory(self, directory, extensions=['.cs', '.js', '.py', '.ts']):
        """Recursively scan a directory for code files"""
        
        directory = Path(directory)
        skip_dirs = {'node_modules', 'bin', 'obj', '.git', 'dist', 'build', '__pycache__', '.vs'}
        
        files_to_scan = []
        for file_path in directory.rglob('*'):
            if any(skip_dir in file_path.parts for skip_dir in skip_dirs):
                continue
            if file_path.suffix in extensions and file_path.is_file():
                files_to_scan.append(file_path)
        
        print(f"\nFound {len(files_to_scan)} files to scan\n")
        
        for idx, file_path in enumerate(files_to_scan, 1):
            print(f"[{idx}/{len(files_to_scan)}] {file_path.name}")
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                self.scan_file(str(file_path), content)
                
            except Exception as e:
                print(f"  ✗ Could not read file: {e}")
    
    def generate_report(self, output_file="vulnerability_report.md"):
        """Generate a markdown report of findings"""
        
        if not self.vulnerabilities:
            print("\n" + "="*50)
            print("✓ SCAN COMPLETE - No vulnerabilities found!")
            print("="*50)
            return
        
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        sorted_vulns = sorted(
            self.vulnerabilities, 
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 3)
        )
        
        high = sum(1 for v in sorted_vulns if v.get('severity') == 'HIGH')
        medium = sum(1 for v in sorted_vulns if v.get('severity') == 'MEDIUM')
        low = sum(1 for v in sorted_vulns if v.get('severity') == 'LOW')
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# Vulnerability Scan Report\n\n")
            f.write(f"**Total Issues Found:** {len(sorted_vulns)}\n\n")
            f.write(f"- 🔴 **HIGH**: {high}\n")
            f.write(f"- 🟡 **MEDIUM**: {medium}\n")
            f.write(f"- 🟢 **LOW**: {low}\n\n")
            f.write("---\n\n")
            
            for i, vuln in enumerate(sorted_vulns, 1):
                severity_emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
                emoji = severity_emoji.get(vuln.get('severity', 'MEDIUM'), '⚪')
                
                f.write(f"## {emoji} Issue #{i}: {vuln.get('type', 'Unknown')}\n\n")
                f.write(f"**Severity:** {vuln.get('severity', 'UNKNOWN')}\n\n")
                f.write(f"**File:** `{vuln.get('file', 'Unknown')}`\n\n")
                f.write(f"**Description:**\n\n{vuln.get('description', 'No description')}\n\n")
                f.write(f"**Recommendation:** {vuln.get('recommendation', 'Manual review')}\n\n")
                f.write("---\n\n")
        
        print("\n" + "="*50)
        print(f"✓ SCAN COMPLETE")
        print(f"  Total Issues: {len(sorted_vulns)}")
        print(f"  HIGH: {high} | MEDIUM: {medium} | LOW: {low}")
        print(f"  Report: {output_file}")
        print("="*50)


if __name__ == "__main__":
    print("="*50)
    print("AI Vulnerability Scanner")
    print("="*50)
    
    OLLAMA_HOST = "http://localhost:11434"
    OLLAMA_MODEL = "codellama:34b"
    
    scanner = VulnerabilityScanner(
        model_name=OLLAMA_MODEL,
        host=OLLAMA_HOST
    )
    
    project_path = "path/to/project"
    
    print(f"\nTarget: {project_path}")
    print(f"Model: {OLLAMA_MODEL}")
    print(f"Ollama Host: {OLLAMA_HOST}")
    
    scanner.scan_directory(project_path, extensions=['.cs'])
    scanner.generate_report("vulnerability_report.md")