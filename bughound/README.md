# BugHound - AI-Powered Bug Bounty MCP Agent

BugHound is an intelligent security testing tool that provides AI-powered bug bounty automation through conversational interfaces using the Model Context Protocol (MCP).

## Features

- **AI-First Design**: Intelligent analysis and decision-making, not just automation
- **Conversational Interface**: Natural language interaction for security testing
- **MCP Integration**: Seamless integration with Claude Desktop and other MCP clients
- **Modular Architecture**: Extensible tool integration framework
- **Smart Workflows**: Context-aware scanning and analysis

## Installation

### Prerequisites

- Python 3.11+
- Claude Desktop (for MCP integration)
- Security tools (subfinder, nmap, etc.)

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd bughound
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure Claude Desktop:
Add to your Claude Desktop configuration:
```json
{
  "mcpServers": {
    "bughound-recon": {
      "command": "python",
      "args": ["-m", "bughound.mcp_servers.recon_server"],
      "cwd": "/path/to/bughound"
    }
  }
}
```

## Usage

Start a conversation with Claude and use natural language to perform security testing:

```
"Scan example.com for subdomains"
"Perform a quick reconnaissance on target.com"
"Analyze the security posture of website.org"
```

## Project Structure

```
bughound/
├── mcp_servers/        # MCP server implementations
├── core/               # Core engine components
├── tools/              # Security tool wrappers
├── workspaces/         # Scan results and data
├── config/             # Configuration files
├── tests/              # Test suite
└── scripts/            # Utility scripts
```

## Development

See [CLAUDE.md](CLAUDE.md) for detailed development instructions.

## License

[License information to be added]