"""Browser-based web crawler for Hunter"""

import asyncio
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Browser, Page

from hunter.config import settings

logger = logging.getLogger(__name__)


@dataclass
class FormData:
    """Represents a form on a web page"""
    action: str
    method: str
    inputs: List[Dict[str, str]]
    buttons: List[Dict[str, str]]
    index: int = 0


@dataclass
class PageData:
    """Represents extracted data from a web page"""
    url: str
    title: str
    forms: List[FormData]
    links: List[Dict[str, str]]


class BrowserCrawler:
    """Crawls web pages using Playwright browser"""
    
    def __init__(self, delay: Optional[float] = None):
        self.delay = delay or settings.delay_between_requests
        self.browser: Optional[Browser] = None
        self.playwright = None
    
    async def __aenter__(self):
        """Initialize browser"""
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close browser"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def crawl_page(self, url: str) -> Optional[PageData]:
        """Crawl a single page and extract data
        
        Args:
            url: URL to crawl
            
        Returns:
            PageData with extracted information
        """
        if not self.browser:
            raise RuntimeError("Browser not initialized. Use 'async with' context manager.")
        
        page = await self.browser.new_page()
        
        try:
            logger.debug(f"Crawling: {url}")
            await asyncio.sleep(self.delay)
            
            response = await page.goto(url, wait_until="networkidle", timeout=30000)
            
            title = await page.title()
            final_url = page.url  # May differ from input due to redirects
            
            # Extract forms
            forms = await self._extract_forms(page)
            
            # Extract links
            links = await self._extract_links(page, final_url)
            
            logger.info(f"Crawled: {final_url} - {len(forms)} form(s), {len(links)} link(s)")
            
            return PageData(
                url=final_url,
                title=title,
                forms=forms,
                links=links
            )
            
        except Exception as e:
            logger.error(f"Crawl error for {url}: {e}")
            return None
        finally:
            await page.close()
    
    async def find_login_pages(self, base_url: str) -> List[str]:
        """Discover login pages by following links
        
        Args:
            base_url: Starting URL
            
        Returns:
            List of login page URLs
        """
        logger.info(f"Discovering login pages from: {base_url}")
        
        page_data = await self.crawl_page(base_url)
        if not page_data:
            return []
        
        login_urls = []
        
        for link in page_data.links:
            href = link.get('href', '')
            text = link.get('text', '').lower()
            
            # Check for login keywords
            login_keywords = ['login', 'signin', 'sign-in', 'log-in', 'authenticate', 'auth']
            
            is_login = any(kw in text for kw in login_keywords) or \
                      any(kw in href.lower() for kw in login_keywords)
            
            if is_login and href.startswith(('http://', 'https://')):
                # Check same domain
                base_domain = urlparse(base_url).netloc
                link_domain = urlparse(href).netloc
                
                if base_domain == link_domain and href not in login_urls:
                    login_urls.append(href)
        
        logger.info(f"Found {len(login_urls)} login page(s)")
        return login_urls
    
    async def _extract_forms(self, page: Page) -> List[FormData]:
        """Extract all forms from a page"""
        forms_js = await page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach((form, idx) => {
                    const inputs = [];
                    form.querySelectorAll('input, textarea, select').forEach(input => {
                        if (input.name && !['submit', 'button', 'hidden', 'file', 'reset'].includes(input.type)) {
                            inputs.push({
                                name: input.name,
                                type: input.type || 'text',
                                id: input.id || '',
                                tagName: input.tagName
                            });
                        }
                    });
                    
                    const buttons = [];
                    form.querySelectorAll('button, input[type="submit"]').forEach(btn => {
                        buttons.push({
                            type: btn.type || 'button',
                            text: (btn.innerText || btn.value || '').trim(),
                            id: btn.id || '',
                            name: btn.name || ''
                        });
                    });
                    
                    if (inputs.length > 0) {
                        forms.push({
                            index: idx,
                            action: form.action || '',
                            method: (form.method || 'get').toLowerCase(),
                            inputs: inputs,
                            buttons: buttons
                        });
                    }
                });
                return forms;
            }
        """)
        
        return [FormData(**form) for form in forms_js]
    
    async def _extract_links(self, page: Page, base_url: str) -> List[Dict[str, str]]:
        """Extract all links from a page"""
        links_js = await page.evaluate("""
            () => {
                const links = [];
                document.querySelectorAll('a').forEach(a => {
                    if (a.href) {
                        links.push({
                            href: a.href,
                            text: (a.innerText || '').trim()
                        });
                    }
                });
                return links;
            }
        """)
        
        # Filter to same domain
        base_domain = urlparse(base_url).netloc
        filtered = []
        seen = set()
        
        for link in links_js:
            href = link['href']
            if href in seen:
                continue
            seen.add(href)
            
            try:
                link_domain = urlparse(href).netloc
                if link_domain == base_domain:
                    filtered.append(link)
            except:
                pass
        
        return filtered
    
    async def submit_form(self, page: Page, form_data: FormData, 
                          field_values: Dict[str, str]) -> Optional[Page]:
        """Submit a form with given field values
        
        Args:
            page: Playwright page object
            form_data: Form data from extract_forms
            field_values: Dict of field_name -> value
            
        Returns:
            Page object after submission (may be new page)
        """
        try:
            # Fill all fields
            for field_name, value in field_values.items():
                try:
                    await page.fill(f"[name='{field_name}']", value)
                except Exception as e:
                    logger.debug(f"Could not fill field {field_name}: {e}")
            
            # Click submit button
            clicked = False
            
            # Try specific button selectors
            for btn in form_data.buttons:
                selectors = []
                if btn.get('id'):
                    selectors.append(f"#{btn['id']}")
                if btn.get('name'):
                    selectors.append(f"[name='{btn['name']}']")
                
                for selector in selectors:
                    try:
                        elem = await page.query_selector(selector)
                        if elem:
                            await elem.click()
                            clicked = True
                            break
                    except:
                        continue
                
                if clicked:
                    break
            
            # Fallback to generic selectors
            if not clicked:
                fallback_selectors = [
                    "input[type='submit']",
                    "button[type='submit']",
                    "button:has-text('Submit')",
                    "button:has-text('Login')",
                    "button:has-text('Sign In')",
                ]
                
                for selector in fallback_selectors:
                    try:
                        elem = await page.query_selector(selector)
                        if elem:
                            await elem.click()
                            clicked = True
                            break
                    except:
                        continue
            
            # Last resort: press Enter in first field
            if not clicked and field_values:
                first_field = list(field_values.keys())[0]
                try:
                    await page.press(f"[name='{first_field}']", "Enter", timeout=5000)
                except Exception as e:
                    logger.debug(f"Could not press Enter in {first_field}: {e}")
            
            # Wait for navigation with shorter timeout
            try:
                await page.wait_for_load_state("networkidle", timeout=3000)
            except:
                pass
            
            return page
            
        except Exception as e:
            logger.debug(f"Form submission error: {e}")
            return None
