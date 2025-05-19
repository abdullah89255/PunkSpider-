#!/usr/bin/env python3
'''
Author      : Stephen Hosom
Last Mod.   : 05.07.2025
Changelog   : 07.21.2013 - Creation
              05.05.2025 - Updated for Python 3, added error handling
              05.06.2025 - Perfected with modular design, async, and rich UI
              05.07.2025 - Fixed DNS errors, added pagination, multiple export formats, and more
Purpose     : The ultimate CLI tool for searching vulnerability databases
              with advanced features like pagination, webhooks, and parallel searches.
'''

__version__ = '3.0.0'

import argparse
import asyncio
import csv
import gzip
import json
import logging
import os
import socket
import sys
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Generator, Any, Optional, List, Set
from urllib.parse import quote

import httpx
import yaml
from bs4 import BeautifulSoup
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.completion import WordCompleter
from rich.console import Console
from rich.table import Table
from tqdm.asyncio import tqdm
from cachetools import TTLCache
from ratelimit import limits, sleep_and_retry

# Constants
CONFIG_FILE = Path.home() / '.punkspider_search.yaml'
HISTORY_FILE = Path.home() / '.punkspider_search_history'
CACHE_TTL = 3600  # Cache results for 1 hour
CACHE_MAXSIZE = 100
DEFAULT_TIMEOUT = 30
DEFAULT_UA = f'PunkSpiderSearch/{__version__}'
LOG_FILE = 'punkspider_search.log'
DEFAULT_RATE_LIMIT = 10  # Requests per minute
MOCK_DATA = [
    {'id': '1', 'timestamp': '2025-05-06T12:00:00', 'title': 'Test Page', 'url': '',
     'bsqli': 0, 'sqli': 1, 'xss': 1}
]

# Initialize rich console
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Cache for search results
cache = TTLCache(maxsize=CACHE_MAXSIZE, ttl=CACHE_TTL)

class SearchBackend(ABC):
    """Abstract base class for search backends."""
    
    @abstractmethod
    async def search(self, searchkey: str, searchvalue: str, bsqli: int = 0, sqli: int = 0, xss: int = 0, 
                     page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    async def health_check(self) -> bool:
        pass

class WebScraperBackend(SearchBackend):
    """Search backend using web scraping with async HTTP requests."""
    
    def __init__(self, base_url: str, timeout: int = DEFAULT_TIMEOUT, api_keys: List[str] = None, rate_limit: int = DEFAULT_RATE_LIMIT):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.api_keys = api_keys or []
        self.current_key_index = 0
        self.rate_limit = rate_limit
        self.client = httpx.AsyncClient(
            headers={'User-Agent': DEFAULT_UA},
            timeout=timeout,
            follow_redirects=True
        )

    @sleep_and_retry
    @limits(calls=DEFAULT_RATE_LIMIT, period=60)
    async def search(self, searchkey: str, searchvalue: str, bsqli: int = 0, sqli: int = 0, xss: int = 0, 
                     page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        """Performs a paginated search by scraping a website."""
        cache_key = f"{searchkey}:{searchvalue}:{bsqli}:{sqli}:{xss}:{page}:{page_size}"
        if cache_key in cache:
            logger.debug("Returning cached results")
            return cache[cache_key]

        try:
            # Validate base_url
            parsed_url = httpx.URL(self.base_url)
            socket.gethostbyname(parsed_url.host)  # Check DNS resolution
            
            headers = {'User-Agent': DEFAULT_UA}
            if self.api_keys:
                headers['Authorization'] = f'Bearer {self.api_keys[self.current_key_index]}'
            
            encoded_value = quote(searchvalue, safe='')
            params = {
                'searchkey': searchkey,
                'q': encoded_value,
                'bsqli': bsqli,
                'sqli': sqli,
                'xss': xss,
                'page': page,
                'page_size': page_size
            }
            url = f"{self.base_url}/search"
            logger.debug(f"Sending request to {url} with params {params}")
            
            response = await self.client.get(url, params=params, headers=headers)
            response.raise_for_status()
            
            # Parse HTML (simplified example)
            soup = BeautifulSoup(response.text, 'html.parser')
            results = soup.select('.result-item') or []
            
            parsed_results = [
                {
                    'id': result.get('data-id', 'N/A'),
                    'timestamp': result.find(class_='timestamp') or 'N/A',
                    'title': result.find(class_='title') or 'N/A',
                    'url': result.find('a', class_='url') or 'N/A',
                    'bsqli': int(result.get('data-bsqli', 0)),
                    'sqli': int(result.get('data-sqli', 0)),
                    'xss': int(result.get('data-xss', 0))
                }
                for result in results
            ]
            
            cache[cache_key] = parsed_results
            return parsed_results
            
        except socket.gaierror as e:
            logger.error(f"DNS resolution failed for {self.base_url}: {e}")
            console.print(f"[red]Error: Cannot resolve {self.base_url}. Use --mock or set a valid --base-url.[/red]")
            raise
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401 and self.api_keys:
                self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
                logger.warning(f"API key failed, rotating to next key")
                return await self.search(searchkey, searchvalue, bsqli, sqli, xss, page, page_size)
            logger.error(f"HTTP error: {e}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Network error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise

    async def health_check(self) -> bool:
        """Checks if the service is reachable."""
        try:
            parsed_url = httpx.URL(self.base_url)
            socket.gethostbyname(parsed_url.host)
            response = await self.client.get(self.base_url, timeout=5)
            response.raise_for_status()
            return True
        except (socket.gaierror, httpx.RequestError, httpx.HTTPStatusError) as e:
            logger.error(f"Health check failed: {e}")
            return False

    async def close(self):
        await self.client.aclose()

class MockBackend(SearchBackend):
    """Mock backend for testing without a live service."""
    
    async def search(self, searchkey: str, searchvalue: str, bsqli: int = 0, sqli: int = 0, xss: int = 0, 
                     page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        logger.info("Using mock backend")
        filtered = [result for result in MOCK_DATA 
                    if (not bsqli or result['bsqli']) and 
                       (not sqli or result['sqli']) and 
                       (not xss or result['xss'])]
        start = (page - 1) * page_size
        return filtered[start:start + page_size]

    async def health_check(self) -> bool:
        return True

def load_config() -> Dict[str, Any]:
    """Loads configuration from YAML or environment variables."""
    config = {
        'base_url': os.getenv('PUNKSPIDER_URL', 'https://hypothetical-punkspider.com'),
        'timeout': int(os.getenv('PUNKSPIDER_TIMEOUT', DEFAULT_TIMEOUT)),
        'searchkey': os.getenv('PUNKSPIDER_SEARCHKEY', 'url'),
        'api_keys': os.getenv('PUNKSPIDER_API_KEYS', '').split(',') if os.getenv('PUNKSPIDER_API_KEYS') else [],
        'rate_limit': int(os.getenv('PUNKSPIDER_RATE_LIMIT', DEFAULT_RATE_LIMIT)),
        'webhook_url': os.getenv('PUNKSPIDER_WEBHOOK_URL', ''),
        'page_size': int(os.getenv('PUNKSPIDER_PAGE_SIZE', 100)),
        'max_pages': int(os.getenv('PUNKSPIDER_MAX_PAGES', 10))
    }
    
    if CONFIG_FILE.exists():
        try:
            with CONFIG_FILE.open('r', encoding='utf-8') as f:
                yaml_config = yaml.safe_load(f) or {}
            config.update(yaml_config)
        except yaml.YAMLError as e:
            logger.warning(f"Invalid YAML config: {e}")
    
    # Secure config file permissions
    if CONFIG_FILE.exists():
        os.chmod(CONFIG_FILE, 0o600)
    
    return config

def get_args(config: Dict[str, Any]) -> argparse.Namespace:
    """Parses command line arguments with config defaults."""
    parser = argparse.ArgumentParser(
        description="Search vulnerability databases with advanced features.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  Search URLs for "bytecapsuleit.com" with XSS:
    punkspider_search.py bytecapsuleit.com -k url -x
  Save JSON results:
    punkspider_search.py login -k title -s -C results.json
  Run in interactive mode:
    punkspider_search.py --interactive
  Test with mock backend:
    punkspider_search.py test --mock
  Check service health:
    punkspider_search.py --health-check
        '''
    )

    parser.add_argument('searchvalue', type=str, nargs='*', default=[''], help='Value(s) to search for.')
    parser.add_argument('-k', '--searchkey', type=str, choices=['url', 'title'], 
                        default=config.get('searchkey'), help='Search by URL or title.')
    parser.add_argument('-C', '--output', type=str, dest='output_location', 
                        default=None, help='Save results to CSV, JSON, or XML file.')
    parser.add_argument('-x', '--xss', action='store_true', help='Include only XSS positives.')
    parser.add_argument('-b', '--bsqli', action='store_true', help='Include only BSQLI positives.')
    parser.add_argument('-s', '--sqli', action='store_true', help='Include only SQLI positives.')
    parser.add_argument('--base-url', type=str, default=config.get('base_url'), 
                        help='Search service base URL.')
    parser.add_argument('--timeout', type=int, default=config.get('timeout'), 
                        help='HTTP request timeout in seconds.')
    parser.add_argument('--api-key', type=str, action='append', default=config.get('api_keys'), 
                        help='API key(s) for authenticated services.')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                        default='INFO', help='Logging verbosity.')
    parser.add_argument('--mock', action='store_true', help='Use mock backend for testing.')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode.')
    parser.add_argument('--health-check', action='store_true', help='Check service availability.')
    parser.add_argument('--columns', type=str, default='id,timestamp,title,url,bsqli,sqli,xss', 
                        help='Comma-separated columns to include (e.g., id,url,xss).')
    parser.add_argument('--sort-by', type=str, choices=['id', 'timestamp', 'bsqli', 'sqli', 'xss'], default=None, 
                        help='Sort results by field.')
    parser.add_argument('--filter-timestamp', type=str, help='Filter results after timestamp (YYYY-MM-DD).')
    parser.add_argument('--deduplicate', type=str, choices=['url', 'id', 'none'], default='none', 
                        help='Deduplicate results by URL or ID.')
    parser.add_argument('--webhook', type=str, default=config.get('webhook_url'), 
                        help='Webhook URL for result notifications.')
    parser.add_argument('--dry-run', action='store_true', help='Simulate search without network/file operations.')
    parser.add_argument('--page-size', type=int, default=config.get('page_size'), 
                        help='Results per page.')
    parser.add_argument('--max-pages', type=int, default=config.get('max_pages'), 
                        help='Maximum pages to fetch.')
    parser.add_argument('--concurrency', type=int, default=1, 
                        help='Number of parallel searches.')

    args = parser.parse_args()

    # Validate inputs
    args.searchvalue = [v.strip() for v in args.searchvalue if v.strip()]
    if not args.searchvalue and not (args.interactive or args.health_check):
        parser.error("searchvalue cannot be empty unless --interactive or --health-check is used.")
    if args.output_location:
        args.output_location = args.output_location.strip()
        ext = args.output_location.lower().rsplit('.', 1)[-1]
        if ext not in ('csv', 'json', 'xml', 'gz'):
            args.output_location += '.csv'
        if not Path(args.output_location).parent.is_dir():
            try:
                Path(args.output_location).parent.mkdir(parents=True)
            except OSError as e:
                parser.error(f"Cannot create output directory: {e}")
    args.columns = [c.strip() for c in args.columns.split(',') if c.strip()]
    if not all(c in ('id', 'timestamp', 'title', 'url', 'bsqli', 'sqli', 'xss') for c in args.columns):
        parser.error("Invalid columns specified.")
    if args.concurrency < 1:
        parser.error("Concurrency must be at least 1.")
    
    return args

def process_args(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Converts arguments to search parameters for each search value."""
    return [{
        'searchkey': args.searchkey,
        'searchvalue': value,
        'bsqli': 1 if args.bsqli else 0,
        'sqli': 1 if args.sqli else 0,
        'xss': 1 if args.xss else 0
    } for value in args.searchvalue]

async def results_generator(backend: SearchBackend, params: Dict[str, Any], max_pages: int, page_size: int) -> Generator[Dict[str, Any], None, None]:
    """Yields paginated search results."""
    for page in range(1, max_pages + 1):
        results = await backend.search(**params, page=page, page_size=page_size)
        if not results:
            break
        for result in results:
            yield result

async def write_output(output_location: str, results: List[Dict[str, Any]], columns: List[str], compress: bool = False) -> None:
    """Writes results to CSV, JSON, or XML with optional compression."""
    try:
        output_path = Path(output_location)
        ext = output_path.suffix.lower().lstrip('.')
        
        filtered_results = [{c: r[c] for c in columns} for r in results]
        
        if ext == 'csv' or (ext == 'gz' and output_location.endswith('.csv.gz')):
            open_func = gzip.open if compress else open
            mode = 'wt' if not compress else 'wt'
            with open_func(output_path, mode, encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=columns, lineterminator='\n')
                writer.writeheader()
                writer.writerows(filtered_results)
        elif ext == 'json' or (ext == 'gz' and output_location.endswith('.json.gz')):
            open_func = gzip.open if compress else open
            mode = 'wt' if not compress else 'wt'
            with open_func(output_path, mode, encoding='utf-8') as f:
                json.dump(filtered_results, f, indent=2)
        elif ext == 'xml' or (ext == 'gz' and output_location.endswith('.xml.gz')):
            open_func = gzip.open if compress else open
            mode = 'wb' if compress else 'w'
            root = ET.Element('results')
            for result in filtered_results:
                item = ET.SubElement(root, 'result')
                for key, value in result.items():
                    elem = ET.SubElement(item, key)
                    elem.text = str(value)
            tree = ET.ElementTree(root)
            with open_func(output_path, mode) as f:
                tree.write(f, encoding='unicode' if not compress else 'utf-8')
        else:
            raise ValueError(f"Unsupported output format: {ext}")
        
        console.print(f"[green]Results written to {output_location}[/green]")
    except IOError as e:
        logger.error(f"Error writing output: {e}")
        raise

async def send_webhook(webhook_url: str, results: List[Dict[str, Any]], columns: List[str]) -> None:
    """Sends results to a webhook URL."""
    if not webhook_url:
        return
    try:
        async with httpx.AsyncClient() as client:
            payload = {'results': [{c: r[c] for c in columns} for r in results]}
            response = await client.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Webhook notification sent")
    except httpx.RequestError as e:
        logger.warning(f"Failed to send webhook: {e}")

def deduplicate_results(results: List[Dict[str, Any]], strategy: str) -> List[Dict[str, Any]]:
    """Removes duplicate results based on strategy."""
    if strategy == 'none':
        return results
    seen: Set[str] = set()
    deduped = []
    for result in results:
        key = result[strategy]
        if key not in seen:
            seen.add(key)
            deduped.append(result)
    return deduped

def sort_results(results: List[Dict[str, Any]], sort_by: Optional[str]) -> List[Dict[str, Any]]:
    """Sorts results by specified field."""
    if not sort_by:
        return results
    return sorted(results, key=lambda x: x[sort_by])

def filter_results(results: List[Dict[str, Any]], filter_timestamp: Optional[str]) -> List[Dict[str, Any]]:
    """Filters results by timestamp."""
    if not filter_timestamp:
        return results
    try:
        from datetime import datetime
        cutoff = datetime.fromisoformat(filter_timestamp.replace('Z', '+00:00'))
        return [r for r in results if datetime.fromisoformat(r['timestamp'].replace('Z', '+00:00')) >= cutoff]
    except ValueError as e:
        logger.warning(f"Invalid timestamp format: {e}")
        return results

def display_results(results: List[Dict[str, Any]], columns: List[str]) -> None:
    """Displays results in a rich table."""
    table = Table(title="Search Results", show_lines=True)
    for col in columns:
        table.add_column(col.upper(), style="cyan" if col == 'id' else "green" if col in ('title', 'url') else "red")
    
    for result in results:
        table.add_row(*[str(result[col]) for col in columns])
    
    console.print(table)

async def interactive_mode(backend: SearchBackend, config: Dict[str, Any]) -> None:
    """Runs an interactive mode with autocomplete."""
    console.print("[bold cyan]Welcome to PunkSpider Search Interactive Mode![/bold cyan]")
    
    session = PromptSession(
        history=FileHistory(str(HISTORY_FILE)),
        completer=WordCompleter(['url', 'title', 'bytecapsuleit.com', 'login'], ignore_case=True)
    )
    
    searchvalue = (await session.prompt_async("Enter search value: ")).strip()
    if not searchvalue:
        console.print("[red]Search value cannot be empty.[/red]")
        return

    searchkey = (await session.prompt_async("Search by [url/title] (default: url): ")).strip() or 'url'
    if searchkey not in ['url', 'title']:
        console.print("[red]Invalid search key. Using 'url'.[/red]")
        searchkey = 'url'

    bsqli = (await session.prompt_async("Filter by BSQLI? [y/N]: ")).strip().lower() == 'y'
    sqli = (await session.prompt_async("Filter by SQLI? [y/N]: ")).strip().lower() == 'y'
    xss = (await session.prompt_async("Filter by XSS? [y/N]: ")).strip().lower() == 'y'
    output = (await session.prompt_async("Save to file? [csv/json/xml/N]: ")).strip().lower()
    output_location = (await session.prompt_async("File path (default: results.csv): ")).strip() or 'results.csv' if output in ('csv', 'json', 'xml') else None
    compress = (await session.prompt_async("Compress output? [y/N]: ")).strip().lower() == 'y' if output_location else False
    
    params = [{
        'searchkey': searchkey,
        'searchvalue': searchvalue,
        'bsqli': 1 if bsqli else 0,
        'sqli': 1 if sqli else 0,
        'xss': 1 if xss else 0
    }]

    results = []
    async for result in tqdm(results_generator(backend, params[0], config['max_pages'], config['page_size']), desc="Fetching results"):
        results.append(result)
    
    if output_location:
        await write_output(output_location, results, config['columns'], compress)
    else:
        display_results(results, config['columns'])

async def health_check(backend: SearchBackend) -> None:
    """Checks service availability."""
    console.print("[yellow]Checking service health...[/yellow]")
    if await backend.health_check():
        console.print("[green]Service is reachable.[/green]")
    else:
        console.print("[red]Service is unreachable. Use --mock or set a valid --base-url.[/red]")
        sys.exit(1)

async def parallel_searches(backend: SearchBackend, params_list: List[Dict[str, Any]], max_pages: int, page_size: int, concurrency: int) -> List[Dict[str, Any]]:
    """Runs multiple searches in parallel."""
    semaphore = asyncio.Semaphore(concurrency)
    
    async def fetch_results(params: Dict[str, Any]) -> List[Dict[str, Any]]:
        async with semaphore:
            results = []
            async for result in results_generator(backend, params, max_pages, page_size):
                results.append(result)
            return results
    
    tasks = [fetch_results(params) for params in params_list]
    results = []
    for task_results in await tqdm.gather(*tasks, desc="Running parallel searches"):
        results.extend(task_results)
    return results

async def main() -> None:
    """Main function to orchestrate the search process."""
    try:
        # Load config and parse arguments
        config = load_config()
        args = get_args(config)
        
        # Set log level
        logger.setLevel(getattr(logging, args.log_level))
        
        # Initialize backend
        backend = MockBackend() if args.mock or args.dry_run else WebScraperBackend(
            args.base_url, args.timeout, args.api_key or config.get('api_keys'), config.get('rate_limit')
        )
        
        if args.health_check:
            await health_check(backend)
            return
        
        if args.interactive:
            await interactive_mode(backend, vars(args))
            return
        
        if args.dry_run:
            console.print("[yellow]Dry run mode: Simulating search...[/yellow]")
            results = MOCK_DATA
        else:
            params_list = process_args(args)
            results = await parallel_searches(backend, params_list, args.max_pages, args.page_size, args.concurrency)
        
        # Process results
        results = deduplicate_results(results, args.deduplicate)
        results = filter_results(results, args.filter_timestamp)
        results = sort_results(results, args.sort_by)
        
        if args.output_location and not args.dry_run:
            await write_output(args.output_location, results, args.columns, args.output_location.endswith('.gz'))
        else:
            display_results(results, args.columns)
        
        if args.webhook and not args.dry_run:
            await send_webhook(args.webhook, results, args.columns)
        
        # Clean up
        if hasattr(backend, 'close'):
            await backend.close()
            
    except KeyboardInterrupt:
        console.print("[yellow]Search interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
