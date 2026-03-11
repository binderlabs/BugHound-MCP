#!/usr/bin/env python3
"""
Workspace Configuration Management for BugHound

Handles configuration settings for workspace behavior including:
- Auto-archiving policies
- Size limits and cleanup
- Report format preferences
- Evidence collection settings
"""

import json
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class ArchiveSettings:
    """Auto-archiving configuration"""
    enabled: bool = True
    max_age_days: int = 30  # Auto-archive after X days
    compression_level: int = 6
    remove_original: bool = False
    preserve_reports: bool = True


@dataclass
class SizeLimits:
    """Workspace size limit configuration"""
    max_workspace_size_mb: int = 1024  # 1GB default
    max_total_workspaces_gb: int = 10  # 10GB total
    cleanup_threshold: float = 0.8  # Cleanup when 80% full
    auto_cleanup_enabled: bool = True


@dataclass
class ReportPreferences:
    """Default report generation preferences"""
    default_formats: List[str] = None
    include_ai_insights: bool = True
    executive_level: bool = False
    include_evidence: bool = True
    auto_generate: bool = True
    
    def __post_init__(self):
        if self.default_formats is None:
            self.default_formats = ["markdown", "html"]


@dataclass
class EvidenceSettings:
    """Evidence collection configuration"""
    auto_collect: bool = True
    max_evidence_per_finding: int = 10
    include_screenshots: bool = True
    include_payloads: bool = True
    include_responses: bool = True
    max_response_size_kb: int = 100
    evidence_formats: List[str] = None
    
    def __post_init__(self):
        if self.evidence_formats is None:
            self.evidence_formats = ["json", "raw", "markdown"]


@dataclass
class SecuritySettings:
    """Security and privacy configuration"""
    anonymize_targets: bool = False
    encrypt_sensitive_data: bool = False
    secure_delete: bool = False
    audit_logging: bool = True
    access_control: bool = False


@dataclass
class PerformanceSettings:
    """Performance and resource configuration"""
    max_concurrent_scans: int = 3
    default_scan_timeout: int = 3600  # 1 hour
    cache_results: bool = True
    cache_ttl_hours: int = 24
    parallel_tool_execution: bool = True


@dataclass
class WorkspaceConfig:
    """Complete workspace configuration"""
    archive_settings: ArchiveSettings = None
    size_limits: SizeLimits = None
    report_preferences: ReportPreferences = None
    evidence_settings: EvidenceSettings = None
    security_settings: SecuritySettings = None
    performance_settings: PerformanceSettings = None
    created_at: str = ""
    last_updated: str = ""
    
    def __post_init__(self):
        if self.archive_settings is None:
            self.archive_settings = ArchiveSettings()
        if self.size_limits is None:
            self.size_limits = SizeLimits()
        if self.report_preferences is None:
            self.report_preferences = ReportPreferences()
        if self.evidence_settings is None:
            self.evidence_settings = EvidenceSettings()
        if self.security_settings is None:
            self.security_settings = SecuritySettings()
        if self.performance_settings is None:
            self.performance_settings = PerformanceSettings()
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        self.last_updated = datetime.now().isoformat()


class WorkspaceConfigManager:
    """Manages workspace configuration settings"""
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to configuration file (default: config/workspace.yaml)
        """
        if config_path is None:
            config_path = Path("config/workspace.yaml")
        
        self.config_path = config_path
        self.config_dir = self.config_path.parent
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Load or create default configuration
        self.config = self._load_config()
    
    def _load_config(self) -> WorkspaceConfig:
        """Load configuration from file or create default"""
        
        try:
            if self.config_path.exists():
                logger.info(f"Loading workspace configuration from {self.config_path}")
                
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    if self.config_path.suffix.lower() == '.yaml' or self.config_path.suffix.lower() == '.yml':
                        config_data = yaml.safe_load(f)
                    else:
                        config_data = json.load(f)
                
                # Convert nested dictionaries back to dataclasses
                return self._dict_to_config(config_data)
            else:
                logger.info("Creating default workspace configuration")
                config = WorkspaceConfig()
                self._save_config(config)
                return config
                
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            logger.info("Using default configuration")
            return WorkspaceConfig()
    
    def _dict_to_config(self, data: Dict[str, Any]) -> WorkspaceConfig:
        """Convert dictionary back to WorkspaceConfig"""
        
        archive_settings = ArchiveSettings(**data.get("archive_settings", {}))
        size_limits = SizeLimits(**data.get("size_limits", {}))
        report_preferences = ReportPreferences(**data.get("report_preferences", {}))
        evidence_settings = EvidenceSettings(**data.get("evidence_settings", {}))
        security_settings = SecuritySettings(**data.get("security_settings", {}))
        performance_settings = PerformanceSettings(**data.get("performance_settings", {}))
        
        return WorkspaceConfig(
            archive_settings=archive_settings,
            size_limits=size_limits,
            report_preferences=report_preferences,
            evidence_settings=evidence_settings,
            security_settings=security_settings,
            performance_settings=performance_settings,
            created_at=data.get("created_at", ""),
            last_updated=data.get("last_updated", "")
        )
    
    def _save_config(self, config: WorkspaceConfig):
        """Save configuration to file"""
        
        try:
            config.last_updated = datetime.now().isoformat()
            config_dict = asdict(config)
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if self.config_path.suffix.lower() == '.yaml' or self.config_path.suffix.lower() == '.yml':
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_dict, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Configuration saved to {self.config_path}")
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
    
    def get_config(self) -> WorkspaceConfig:
        """Get current configuration"""
        return self.config
    
    def update_config(self, **kwargs) -> bool:
        """
        Update configuration settings
        
        Args:
            **kwargs: Configuration fields to update
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            # Update archive settings
            if 'archive_settings' in kwargs:
                archive_data = kwargs['archive_settings']
                if isinstance(archive_data, dict):
                    for key, value in archive_data.items():
                        if hasattr(self.config.archive_settings, key):
                            setattr(self.config.archive_settings, key, value)
            
            # Update size limits
            if 'size_limits' in kwargs:
                size_data = kwargs['size_limits']
                if isinstance(size_data, dict):
                    for key, value in size_data.items():
                        if hasattr(self.config.size_limits, key):
                            setattr(self.config.size_limits, key, value)
            
            # Update report preferences
            if 'report_preferences' in kwargs:
                report_data = kwargs['report_preferences']
                if isinstance(report_data, dict):
                    for key, value in report_data.items():
                        if hasattr(self.config.report_preferences, key):
                            setattr(self.config.report_preferences, key, value)
            
            # Update evidence settings
            if 'evidence_settings' in kwargs:
                evidence_data = kwargs['evidence_settings']
                if isinstance(evidence_data, dict):
                    for key, value in evidence_data.items():
                        if hasattr(self.config.evidence_settings, key):
                            setattr(self.config.evidence_settings, key, value)
            
            # Update security settings
            if 'security_settings' in kwargs:
                security_data = kwargs['security_settings']
                if isinstance(security_data, dict):
                    for key, value in security_data.items():
                        if hasattr(self.config.security_settings, key):
                            setattr(self.config.security_settings, key, value)
            
            # Update performance settings
            if 'performance_settings' in kwargs:
                performance_data = kwargs['performance_settings']
                if isinstance(performance_data, dict):
                    for key, value in performance_data.items():
                        if hasattr(self.config.performance_settings, key):
                            setattr(self.config.performance_settings, key, value)
            
            # Save updated configuration
            self._save_config(self.config)
            return True
            
        except Exception as e:
            logger.error(f"Failed to update configuration: {e}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults"""
        
        try:
            self.config = WorkspaceConfig()
            self._save_config(self.config)
            logger.info("Configuration reset to defaults")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reset configuration: {e}")
            return False
    
    def validate_config(self) -> Dict[str, List[str]]:
        """
        Validate current configuration
        
        Returns:
            Dict with validation errors by category
        """
        
        errors = {}
        
        # Validate archive settings
        archive_errors = []
        if self.config.archive_settings.max_age_days < 1:
            archive_errors.append("max_age_days must be at least 1")
        if not 1 <= self.config.archive_settings.compression_level <= 9:
            archive_errors.append("compression_level must be between 1 and 9")
        if archive_errors:
            errors["archive_settings"] = archive_errors
        
        # Validate size limits
        size_errors = []
        if self.config.size_limits.max_workspace_size_mb < 1:
            size_errors.append("max_workspace_size_mb must be positive")
        if self.config.size_limits.max_total_workspaces_gb < 1:
            size_errors.append("max_total_workspaces_gb must be positive")
        if not 0.1 <= self.config.size_limits.cleanup_threshold <= 1.0:
            size_errors.append("cleanup_threshold must be between 0.1 and 1.0")
        if size_errors:
            errors["size_limits"] = size_errors
        
        # Validate evidence settings
        evidence_errors = []
        if self.config.evidence_settings.max_evidence_per_finding < 1:
            evidence_errors.append("max_evidence_per_finding must be positive")
        if self.config.evidence_settings.max_response_size_kb < 1:
            evidence_errors.append("max_response_size_kb must be positive")
        if evidence_errors:
            errors["evidence_settings"] = evidence_errors
        
        # Validate performance settings
        performance_errors = []
        if self.config.performance_settings.max_concurrent_scans < 1:
            performance_errors.append("max_concurrent_scans must be positive")
        if self.config.performance_settings.default_scan_timeout < 60:
            performance_errors.append("default_scan_timeout must be at least 60 seconds")
        if self.config.performance_settings.cache_ttl_hours < 1:
            performance_errors.append("cache_ttl_hours must be positive")
        if performance_errors:
            errors["performance_settings"] = performance_errors
        
        return errors
    
    def export_config(self, export_path: Path, format: str = "yaml") -> bool:
        """
        Export configuration to file
        
        Args:
            export_path: Export destination
            format: Export format ('yaml' or 'json')
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            config_dict = asdict(self.config)
            
            with open(export_path, 'w', encoding='utf-8') as f:
                if format.lower() == 'yaml':
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_dict, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Configuration exported to {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export configuration: {e}")
            return False
    
    def import_config(self, import_path: Path) -> bool:
        """
        Import configuration from file
        
        Args:
            import_path: File to import from
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                if import_path.suffix.lower() in ['.yaml', '.yml']:
                    config_data = yaml.safe_load(f)
                else:
                    config_data = json.load(f)
            
            # Validate imported configuration
            imported_config = self._dict_to_config(config_data)
            temp_config = self.config
            self.config = imported_config
            
            validation_errors = self.validate_config()
            if validation_errors:
                self.config = temp_config  # Restore original
                logger.error(f"Imported configuration is invalid: {validation_errors}")
                return False
            
            # Save imported configuration
            self._save_config(self.config)
            logger.info(f"Configuration imported from {import_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import configuration: {e}")
            return False
    
    def get_setting(self, category: str, setting: str) -> Any:
        """
        Get specific setting value
        
        Args:
            category: Setting category (e.g., 'archive_settings')
            setting: Setting name (e.g., 'max_age_days')
            
        Returns:
            Setting value or None if not found
        """
        
        try:
            category_obj = getattr(self.config, category)
            return getattr(category_obj, setting)
        except AttributeError:
            return None
    
    def set_setting(self, category: str, setting: str, value: Any) -> bool:
        """
        Set specific setting value
        
        Args:
            category: Setting category
            setting: Setting name  
            value: New value
            
        Returns:
            True if successful, False otherwise
        """
        
        try:
            category_obj = getattr(self.config, category)
            setattr(category_obj, setting, value)
            self._save_config(self.config)
            return True
        except AttributeError:
            return False


# Global configuration instance
_config_manager = None


def get_config_manager() -> WorkspaceConfigManager:
    """Get global configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = WorkspaceConfigManager()
    return _config_manager


def get_workspace_config() -> WorkspaceConfig:
    """Get current workspace configuration"""
    return get_config_manager().get_config()


# Convenience functions for common settings
def should_auto_archive() -> bool:
    """Check if auto-archiving is enabled"""
    return get_workspace_config().archive_settings.enabled


def get_max_workspace_size() -> int:
    """Get maximum workspace size in MB"""
    return get_workspace_config().size_limits.max_workspace_size_mb


def get_default_report_formats() -> List[str]:
    """Get default report formats"""
    return get_workspace_config().report_preferences.default_formats


def should_auto_collect_evidence() -> bool:
    """Check if evidence auto-collection is enabled"""
    return get_workspace_config().evidence_settings.auto_collect


def get_max_concurrent_scans() -> int:
    """Get maximum concurrent scans allowed"""
    return get_workspace_config().performance_settings.max_concurrent_scans