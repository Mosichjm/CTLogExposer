# CTLogExposer - Multi-Source Subdomain Enumeration Tool

## 📋 Overview

CTLogExposer is a powerful subdomain enumeration tool that aggregates data from multiple Certificate Transparency (CT) logs and subdomain intelligence sources. Unlike traditional CT log scrapers that rely on a single source, this tool queries 11+ different APIs and databases to provide comprehensive subdomain discovery with intelligent deduplication and DNS resolution.

## 🎯 Purpose

Bug bounty hunters, penetration testers, and security researchers need comprehensive attack surface mapping. A single CT log source often misses subdomains due to:
- Rate limiting
- Incomplete certificate indexing
- API failures or downtime
- Regional certificate authorities not indexed by all sources

CTLogExposer solves this by:
1. **Querying multiple sources simultaneously** - Maximizes subdomain discovery
2. **Intelligent error handling** - Continues even if sources fail
3. **Automatic deduplication** - Removes duplicates across all sources
4. **DNS resolution** - Identifies live vs dead subdomains
5. **Detailed statistics** - Shows which sources contributed most domains

## 🚀 Key Features

### Multi-Source Intelligence
- **11 subdomain sources** including:
  - crt.sh (Comodo CT logs)
  - Certspotter (SSLMate)
  - HackerTarget
  - ThreatCrowd
  - AlienVault OTX
  - Anubis
  - BufferOver
  - URLScan.io
  - VirusTotal (API key required)
  - SecurityTrails (API key required)
  - Shodan (API key required)

### Intelligent Processing
- **Automatic deduplication** - Tracks duplicates per source
- **DNS resolution** - Separates live domains from dead entries
- **Rate limiting** - Respects API limits with intelligent backoff
- **Retry logic** - Handles transient failures gracefully
- **Encoding fixes** - Works flawlessly on Windows/Linux

### Robust Error Handling
- Invalid JSON response recovery
- BOM (Byte Order Mark) stripping
- HTTP status code handling (200, 429, 404)
- Timeout and connection error recovery
- Per-source exception handling

### Detailed Reporting
- Live subdomain list
- Resolved IP addresses
- Domains with no DNS records
- Source contribution statistics
- Duplicate tracking per source
- Top contributing sources ranking

## 📊 Output Files

```
C:\Users\Owner\Desktop\output\
├── domain_output.txt      # All unique subdomains found
├── ip_output.txt          # Resolved IP addresses (if -u flag used)
└── no_dns_output.txt      # Subdomains with no DNS record
```

## 🛠️ Technical Architecture

### Core Components

**1. Multi-Source Collection Engine**
```python
CT_SOURCES = [
    {'name': 'crt.sh', 'url': '...', 'parser': 'crtsh'},
    {'name': 'certspotter', 'url': '...', 'parser': 'certspotter'},
    # ... 9 more sources
]
```

**2. Parser System**
- Each source has a custom parser to handle unique response formats
- Supports JSON, plain text, and CSV responses
- Normalizes all data into a unified format

**3. Deduplication System**
- Uses Python sets for O(1) duplicate checking
- Tracks duplicates per source for statistics
- Normalizes domains (lowercase, wildcard removal)

**4. DNS Resolution Pool**
- Concurrent resolution using gevent
- Configurable rate limiting (default: 5 req/s)
- Separates live vs dead domains

## 💻 Usage

### Basic Usage
```bash
python ct-exposer.py -d example.com
```

### With IP Resolution
```bash
python ct-exposer.py -d example.com -u
```

### Command-Line Arguments
- `-d, --domain` (required) - Target domain to enumerate
- `-u, --urls` (optional) - Resolve and output IP addresses

## 📈 Example Output

```
[+]: Starting CT log enumeration for example.com
[+]: Querying 11 different sources...

[+]: Querying crt.sh...
    [+] Found 847 domain(s) from crt.sh (847 new, 0 duplicates)
[+]: Querying certspotter...
    [+] Found 623 domain(s) from certspotter (156 new, 467 duplicates)
[+]: Querying hackertarget...
    [+] Found 234 domain(s) from hackertarget (89 new, 145 duplicates)

[+]: ========== SUMMARY ==========
[+]: Total unique domains found: 1,247
[+]: Total duplicates filtered: 892

[+]: Top sources by new domains:
    1. crt.sh: 847 new domains
    2. certspotter: 156 new domains
    3. hackertarget: 89 new domains

[+]: Resolving 1,247 domain(s)...

[+]: ========== FINAL STATS ==========
[+]: Unique domains: 1,247
[+]: Resolved IPs: 982
[+]: No DNS record: 265
[+]: Duplicates removed: 892
```

## 🔑 API Key Configuration

Some sources require API keys for access. Add your keys to the `API_KEYS` dictionary:

```python
API_KEYS = {
    'securitytrails': 'YOUR_KEY_HERE',
    'shodan': 'YOUR_KEY_HERE',
    'virustotal': 'YOUR_KEY_HERE',
}
```

**Free API Keys Available:**
- SecurityTrails: https://securitytrails.com/
- Shodan: https://www.shodan.io/
- VirusTotal: https://www.virustotal.com/

Sources without configured API keys are automatically skipped.

## 🔧 Dependencies

```bash
pip install requests gevent
```

### Requirements
- Python 3.7+
- `requests` - HTTP library
- `gevent` - Concurrent DNS resolution
- Standard library: `argparse`, `socket`, `json`, `os`, `time`

## 🎓 Use Cases

### 1. Bug Bounty Reconnaissance
Discover the full attack surface of a target domain before starting security testing.

### 2. Asset Discovery
Organizations can use this to discover all subdomains (including forgotten ones) in their infrastructure.

### 3. Competitive Intelligence
Security teams can monitor competitor infrastructure and technology choices.

### 4. Threat Intelligence
Identify potentially malicious subdomains or certificate anomalies.

### 5. Continuous Monitoring
Run daily to detect new subdomains as they're created (great for CI/CD pipelines).

## 🔒 Security Considerations

- **Rate Limiting**: Respects API rate limits to avoid blacklisting
- **User-Agent**: Uses identifiable UA for ethical disclosure
- **No Exploitation**: Discovery tool only - does not perform attacks
- **SSL Verification**: Disabled for flexibility (warnings suppressed)

## 🚧 Limitations

- Rate limits on free API tiers (upgrade for higher volume)
- Some sources may be temporarily unavailable
- DNS resolution can be slow for large domain sets
- Wildcard certificates may produce many subdomains

## 🔮 Future Enhancements

- [ ] Add more CT log sources (Cloudflare, Google CT)
- [ ] Implement caching to avoid re-querying same domains
- [ ] Add JSON output format for pipeline integration
- [ ] Implement async/await for better performance
- [ ] Add progress bars for long-running scans
- [ ] Export to CSV/Excel formats
- [ ] Integration with subdomain takeover detection
- [ ] Add historical comparison (detect new subdomains)

## 📝 Integration with Security Pipeline

CTLogExposer Enhanced integrates seamlessly with other security tools:

```bash
# Step 1: Subdomain enumeration
python ct-exposer.py -d target.com -u

# Step 2: Port scanning with Nmap
nmap -iL output/domain_output.txt -p 80,443,8080,8443 -oA nmap_results

# Step 3: Web application scanning
nuclei -l output/domain_output.txt -t cves/ -o nuclei_results.txt

# Step 4: Screenshot capture
cat output/domain_output.txt | aquatone
```

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional CT log sources
- New parser implementations
- Performance optimizations
- Documentation improvements
- Bug fixes and error handling

## 📜 License

MIT License - Feel free to use in commercial and open-source projects

## 👨‍💻 Author

Created for security researchers and bug bounty hunters who need comprehensive subdomain enumeration without manual source switching.

## 🙏 Acknowledgments

- Original CT-Exposer concept
- Certificate Transparency project
- All the API providers (crt.sh, Certspotter, HackerTarget, etc.)
- Security research community

---

## 📸 Screenshots

### Successful Multi-Source Enumeration
```
[+]: Starting CT log enumeration for amazon.com
[+]: Querying 11 different sources...

[+]: Querying crt.sh...
    [+] Found 2,847 domain(s) from crt.sh (2,847 new, 0 duplicates)
[+]: Querying certspotter...
    [+] Found 1,923 domain(s) from certspotter (456 new, 1,467 duplicates)
...
```

### Domain Resolution Statistics
```
[+]: ========== FINAL STATS ==========
[+]: Unique domains: 3,421
[+]: Resolved IPs: 2,987
[+]: No DNS record: 434
[+]: Duplicates removed: 6,891
```

---

**⭐ Star this repo if it helped you discover hidden attack surface!**
