"""Subdomain enumeration module for Hunter"""

import asyncio
import logging
import subprocess
from typing import List, Set
from hunter.config import settings

logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Enumerate subdomains using external tools"""
    
    def __init__(self):
        self.subfinder_path = settings.subfinder_path
        self.assetfinder_path = settings.assetfinder_path
    
    async def enumerate(self, domain: str) -> List[str]:
        """Enumerate subdomains for a target domain"""
        logger.info(f"Starting subdomain enumeration for {domain}")
        
        subdomains: Set[str] = set()
        
        # Try subfinder first
        try:
            subfinder_results = await self._run_subfinder(domain)
            subdomains.update(subfinder_results)
            logger.info(f"Subfinder found {len(subfinder_results)} subdomains")
        except Exception as e:
            logger.warning(f"Subfinder failed: {e}")
        
        # Fallback to assetfinder
        if len(subdomains) < 10:
            try:
                assetfinder_results = await self._run_assetfinder(domain)
                subdomains.update(assetfinder_results)
                logger.info(f"Assetfinder found {len(assetfinder_results)} subdomains")
            except Exception as e:
                logger.warning(f"Assetfinder failed: {e}")
        
        # If no tools available, use basic wordlist
        if not subdomains:
            logger.info("Using fallback wordlist enumeration")
            subdomains = await self._fallback_enum(domain)
        
        # Clean and validate
        results = self._clean_results(subdomains, domain)
        logger.info(f"Total unique subdomains found: {len(results)}")
        
        return sorted(results)
    
    async def _run_subfinder(self, domain: str) -> List[str]:
        """Run subfinder tool"""
        cmd = [self.subfinder_path, "-d", domain, "-silent"]
        
        try:
            result = await self._run_subprocess(cmd)
            return [s.strip() for s in result.split("\n") if s.strip()]
        except FileNotFoundError:
            logger.warning("subfinder not found in PATH")
            return []
    
    async def _run_assetfinder(self, domain: str) -> List[str]:
        """Run assetfinder tool"""
        cmd = [self.assetfinder_path, "--subs-only", domain]
        
        try:
            result = await self._run_subprocess(cmd)
            return [s.strip() for s in result.split("\n") if s.strip()]
        except FileNotFoundError:
            logger.warning("assetfinder not found in PATH")
            return []
    
    async def _run_subprocess(self, cmd: List[str]) -> str:
        """Run subprocess and return output"""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), 
            timeout=300  # 5 minute timeout
        )
        
        if proc.returncode != 0 and stderr:
            logger.debug(f"Subprocess stderr: {stderr.decode()}")
        
        return stdout.decode()
    
    async def _fallback_enum(self, domain: str) -> Set[str]:
        """Fallback enumeration using common subdomain wordlist"""
        common_subdomains = [
            "www", "mail", "ftp", "localhost", "admin", "portal",
            "api", "test", "dev", "staging", "prod", "demo",
            "blog", "shop", "store", "app", "mobile", "cdn",
            "static", "assets", "media", "images", "docs",
            "support", "help", "forum", "wiki", "news",
            "secure", "vpn", "remote", "login", "auth",
            "dashboard", "panel", "cp", "control",
            "api-v1", "api-v2", "api-v3", "rest", "graphql",
            "webhook", "callback", "oauth", "sso",
            "internal", "intranet", "corp", "enterprise",
            "backup", "archive", "old", "legacy", "v1", "v2"
        ]
        
        subdomains = set()
        subdomains.add(domain)  # Always include root domain
        
        for sub in common_subdomains:
            subdomains.add(f"{sub}.{domain}")
        
        return subdomains
    
    def _clean_results(self, subdomains: Set[str], root_domain: str) -> List[str]:
        """Clean and validate subdomain results"""
        cleaned = []
        
        for subdomain in subdomains:
            subdomain = subdomain.strip().lower()
            
            # Remove wildcards and invalid chars
            subdomain = subdomain.replace("*.", "")
            
            # Basic validation
            if not subdomain or " " in subdomain:
                continue
            
            # Must be related to root domain
            if not (subdomain == root_domain or subdomain.endswith(f".{root_domain}")):
                continue
            
            cleaned.append(subdomain)
        
        return cleaned
