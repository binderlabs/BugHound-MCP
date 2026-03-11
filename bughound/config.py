"""
BugHound Configuration

Stores API keys and global settings.
"""

import os

# OpenRouter API Key for Grok
# In production, this should be an environment variable
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# Model to use
AI_MODEL = "x-ai/grok-4.1-fast"
