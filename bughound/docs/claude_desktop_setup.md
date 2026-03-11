# Claude Desktop Integration Guide

This guide will help you integrate BugHound with Claude Desktop to test the MCP server functionality.

## Quick Setup

### 1. Verify Server Works

First, ensure the BugHound MCP server is working:

```bash
# Test the server functionality
cd /home/kali/AI/developing/BugHound/bughound
python scripts/test_claude_integration.py

# Verify the exact command that Claude Desktop will use
./scripts/verify_mcp_command.sh
```

### 2. Find Claude Desktop Configuration

Locate your Claude Desktop configuration file:

- **Linux**: `~/.config/claude-desktop/claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### 3. Add BugHound Configuration

Add the following configuration to your Claude Desktop config file:

```json
{
  "mcpServers": {
    "bughound-recon": {
      "command": "python3",
      "args": ["-m", "mcp_servers.recon_server"],
      "cwd": "/home/kali/AI/developing/BugHound/bughound",
      "env": {
        "PYTHONPATH": "/home/kali/AI/developing/BugHound/bughound",
        "BUGHOUND_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Important**: Update the `cwd` path to match your actual BugHound installation path.

### 4. Restart Claude Desktop

Close and restart the Claude Desktop application to load the new MCP server configuration.

## Testing the Integration

### Basic Connectivity Test

In a new Claude Desktop conversation, try:

```
Use the test_connection tool to verify BugHound is working
```

### Custom Message Test

```
Test the connection to BugHound with the message "hello world"
```

### Expected Response

You should see a response like:

```
✅ BugHound MCP Server Test

Status: success
Message: BugHound is working!
Echo: hello world
Server: bughound-recon
Version: 0.1.0

The reconnaissance server is ready for use!
```

## Troubleshooting

### Common Issues

1. **Server not found**
   - Verify the `cwd` path in configuration is correct
   - Ensure Python 3.11+ is installed and accessible as `python3`
   - Check that all required files exist in the project directory

2. **Permission errors**
   - Ensure Claude Desktop has permission to execute Python
   - Check that the project directory is readable

3. **Import errors**
   - Verify the `PYTHONPATH` environment variable is set correctly
   - Ensure all required dependencies are installed

### Debug Steps

1. **Check configuration validity**:
   ```bash
   python scripts/test_claude_integration.py
   ```

2. **Test exact command**:
   ```bash
   cd /home/kali/AI/developing/BugHound/bughound
   python3 -m mcp_servers.recon_server
   ```

3. **Check Claude Desktop logs**:
   - Look for error messages in Claude Desktop's console/logs
   - Common log locations vary by OS

4. **Verify dependencies**:
   ```bash
   cd /home/kali/AI/developing/BugHound/bughound
   python3 -c "import mcp.server; print('MCP library available')"
   ```

## What's Next

Once the test_connection tool works in Claude Desktop:

1. ✅ **Basic MCP integration confirmed**
2. 🚀 **Ready to add real reconnaissance tools**
3. 🛠️ **Can expand with subfinder, nmap, and other security tools**
4. 🤖 **Can add AI-powered analysis features**

## Configuration Files

- **Server config**: `config/claude_desktop_config.json`
- **Test script**: `scripts/test_claude_integration.py`
- **Verification**: `scripts/verify_mcp_command.sh`
- **Server code**: `mcp_servers/recon_server.py`

## Support

If you encounter issues:

1. Run the test scripts to isolate the problem
2. Check the troubleshooting section above
3. Verify your Claude Desktop version supports MCP
4. Ensure all file paths are correct for your system

---

*This guide is for BugHound v0.1.0 - Phase 1 Development*