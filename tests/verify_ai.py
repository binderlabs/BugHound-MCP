#!/usr/bin/env python3
"""
Verification Script for AI Client
Tests connection to OpenRouter (Grok) and prioritization logic.
"""

import logging
import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bughound.core.ai_client import AIClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_ai")

def main():
    logger.info("🧠 Verifying AI Client (Grok)...")
    
    try:
        client = AIClient()
        logger.info("✅ AI Client initialized")
        
        # Test Data
        subdomains = [
            "www.example.com",
            "dev.example.com",
            "api.example.com",
            "test-env.example.com",
            "legacy-portal.example.com",
            "blog.example.com"
        ]
        
        logger.info(f"📤 Sending {len(subdomains)} subdomains for prioritization...")
        
        results = client.prioritize_subdomains(subdomains)
        
        if results:
            logger.info("✅ AI Response Received!")
            logger.info("📊 Prioritization Results:")
            print(json.dumps(results, indent=2))
            
            # Check if we got High priority items
            high_priority = [r for r in results if r.get("priority") == "High"]
            if high_priority:
                logger.info(f"🎯 Success! Identified {len(high_priority)} High Priority targets.")
            else:
                logger.warning("⚠️ No High priority targets identified (might be expected for this list).")
        else:
            logger.error("❌ No results returned from AI.")
            
    except Exception as e:
        logger.error(f"❌ Verification failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
