import requests
from bs4 import BeautifulSoup
import time
import csv
import json
import argparse
import os
import re
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from datetime import datetime, timedelta
import calendar

# === CONFIGURATION ===
ITEMS_PER_PAGE = 30
BASE_URL = "https://steamcommunity.com/workshop/browse/"

# Calculate optimal concurrent pages based on CPU cores
# Max 10 pages, but don't exceed (CPU cores - 1) to leave resources for OS
_cpu_count = os.cpu_count() or 1  # Fallback to 1 if cpu_count() returns None
MAX_CONCURRENT_PAGES = min(10, max(1, _cpu_count - 1)) if _cpu_count > 1 else 1

MAX_SAFE_PAGES = 1667  # Steam's hard limit on pagination
MAX_SAFE_ITEMS = MAX_SAFE_PAGES * ITEMS_PER_PAGE  # 50,010 items

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/114.0.0.0 Safari/537.36"
    )
}

def date_to_timestamp(date_str):
    """Convert YYYY-MM-DD date string to Unix timestamp"""
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return int(dt.timestamp())
    except ValueError:
        print(f"Invalid date format: {date_str}. Use YYYY-MM-DD format.")
        return None

def timestamp_to_date(timestamp):
    """Convert Unix timestamp to YYYY-MM-DD date string"""
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")

def generate_monthly_ranges(start_date, end_date):
    """Generate monthly date ranges between start_date and end_date"""
    ranges = []
    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
    end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    
    current = start_dt
    while current <= end_dt:
        # Start of current month
        month_start = current.replace(day=1)
        
        # End of current month
        last_day = calendar.monthrange(current.year, current.month)[1]
        month_end = current.replace(day=last_day)
        
        # Don't go past the specified end date
        if month_end > end_dt:
            month_end = end_dt
        
        ranges.append((
            int(month_start.timestamp()),
            int(month_end.timestamp()),
            month_start.strftime("%Y-%m-%d"),
            month_end.strftime("%Y-%m-%d")
        ))
        
        # Move to next month
        if current.month == 12:
            current = current.replace(year=current.year + 1, month=1)
        else:
            current = current.replace(month=current.month + 1)
    
    return ranges

def build_url(app_id, page, date_start=None, date_end=None, required_tags=None, excluded_tags=None):
    params = {
        "appid": app_id,
        "section": "readytouseitems",
        "actualsort": "mostrecent",
        "p": page,
        "numperpage": ITEMS_PER_PAGE,
        "browsesort": "mostrecent",
        "days": 0,
        "created_date_range_filter_start": date_start or 0,
        "created_date_range_filter_end": date_end or 0,
        "updated_date_range_filter_start": 0,
        "updated_date_range_filter_end": 0
    }
    
    # Add required tags if provided
    if required_tags:
        for tag in required_tags:
            params[f"requiredtags[]"] = tag
    
    # Add excluded tags if provided  
    if excluded_tags:
        for tag in excluded_tags:
            params[f"excludedtags[]"] = tag
    
    return BASE_URL + "?" + "&".join(f"{k}={v}" for k, v in params.items())

def get_max_page(app_id, date_start=None, date_end=None, required_tags=None, excluded_tags=None):
    url = build_url(app_id, 1, date_start, date_end, required_tags, excluded_tags)
    print("Fetching page 1 to determine total number of pages...")
    response = requests.get(url, headers=HEADERS)
    if not response.ok:
        print("Failed to retrieve page 1 for pagination detection.")
        return None

    soup = BeautifulSoup(response.text, "html.parser")
    paging_div = soup.find("div", class_="workshopBrowsePagingControls")
    if not paging_div:
        print("Pagination controls not found.")
        return None

    page_links = paging_div.find_all("a", class_="pagelink")
    page_numbers = []
    for link in page_links:
        try:
            num_text = link.text.strip().replace(',', '')
            num = int(num_text)
            page_numbers.append(num)
        except ValueError:
            continue

    if not page_numbers:
        print("No numeric page links found in pagination.")
        return None

    max_page = max(page_numbers)
    print(f"Detected max page: {max_page}")
    
    # Warn if we're hitting the Steam limit
    if max_page >= MAX_SAFE_PAGES:
        print(f"WARNING: Detected {max_page} pages, which exceeds Steam's safe limit of {MAX_SAFE_PAGES}.")
        print("Consider using date range filters to break this into smaller chunks.")
    
    return max_page

def fetch_page(app_id, page_num, date_start=None, date_end=None, required_tags=None, excluded_tags=None):
    """Fetch a single page and return the response and page number"""
    url = build_url(app_id, page_num, date_start, date_end, required_tags, excluded_tags)
    try:
        response = requests.get(url, headers=HEADERS)
        return page_num, response, url
    except Exception as e:
        return page_num, None, url

def parse_items_thread_safe(html, page_num, seen_ids_lock, seen_ids, stats_lock, stats):
    """Thread-safe version of parse_items"""
    soup = BeautifulSoup(html, "html.parser")
    items = []
    local_stats = {'total_found': 0, 'added': 0, 'skipped': 0}

    for a_tag in soup.find_all("a", class_="item_link"):
        href = a_tag.get("href")
        if not href or "filedetails" not in href:
            continue

        id_part = href.split("id=")[-1].split("&")[0]
        local_stats['total_found'] += 1

        # Thread-safe check and update of seen_ids
        with seen_ids_lock:
            if id_part in seen_ids:
                local_stats['skipped'] += 1
                continue
            
            title_div = a_tag.find("div", class_="workshopItemTitle")
            title = title_div.text.strip() if title_div else "Unknown Title"

            items.append({"id": id_part, "title": title, "url": href})
            seen_ids.add(id_part)
            local_stats['added'] += 1

    # Thread-safe update of global stats
    with stats_lock:
        stats['total_found'] += local_stats['total_found']
        stats['added'] += local_stats['added']
        stats['skipped'] += local_stats['skipped']

    return items

def parse_items(html, seen_ids, stats):
    soup = BeautifulSoup(html, "html.parser")
    items = []

    for a_tag in soup.find_all("a", class_="item_link"):
        href = a_tag.get("href")
        if not href or "filedetails" not in href:
            continue

        id_part = href.split("id=")[-1].split("&")[0]
        stats['total_found'] += 1

        if id_part in seen_ids:
            stats['skipped'] += 1
            continue

        title_div = a_tag.find("div", class_="workshopItemTitle")
        title = title_div.text.strip() if title_div else "Unknown Title"

        items.append({"id": id_part, "title": title, "url": href})
        seen_ids.add(id_part)
        stats['added'] += 1

    return items

def save_to_csv(data, filename):
    existing_ids = set()
    existing_data = []
    
    # Read existing data if file exists
    if os.path.exists(filename):
        with open(filename, mode="r", newline='', encoding="utf-8-sig") as f:  # utf-8-sig handles BOM
            reader = csv.DictReader(f)
            for row in reader:
                # Clean up any BOM or whitespace issues in keys
                cleaned_row = {}
                for key, value in row.items():
                    clean_key = key.strip().lstrip('\ufeff') if key else 'id'  # Remove BOM and whitespace
                    cleaned_row[clean_key] = value
                existing_data.append(cleaned_row)
                existing_ids.add(cleaned_row.get('id', ''))
    
    # Only proceed if we have new data to add
    if not data:
        print("No new data to save to CSV")
        return
    
    # Filter out duplicates from new data
    new_data = []
    for item in data:
        if item['id'] not in existing_ids:
            new_data.append(item)
            existing_ids.add(item['id'])
    
    # Only write if we have new data or existing data
    if new_data or existing_data:
        # Combine existing and new data
        all_data = existing_data + new_data
        
        # Write all data back to file
        with open(filename, mode="w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["id", "title", "url"])
            writer.writeheader()
            writer.writerows(all_data)
        
        if new_data:
            print(f"Added {len(new_data)} new items to CSV")
        else:
            print("No new items to add (all were duplicates)")
    else:
        print("No data to write to CSV")

def save_to_json(data, filename):
    existing = []
    existing_ids = set()
    
    # Read existing data if file exists
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            try:
                existing = json.load(f)
                for item in existing:
                    existing_ids.add(item.get('id', ''))
            except json.JSONDecodeError:
                existing = []
    
    # Only proceed if we have new data to add
    if not data:
        print("No new data to save to JSON")
        return
    
    # Filter out duplicates from new data
    new_data = []
    for item in data:
        if item['id'] not in existing_ids:
            new_data.append(item)
            existing_ids.add(item['id'])
    
    # Only write if we have new data or existing data
    if new_data or existing:
        # Combine existing and new data
        all_data = existing + new_data
        
        # Write all data back to file
        with open(filename, mode="w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, ensure_ascii=False)
        
        if new_data:
            print(f"Added {len(new_data)} new items to JSON")
        else:
            print("No new items to add (all were duplicates)")
    else:
        print("No data to write to JSON")

def load_seen_ids(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r") as f:
        return set(line.strip() for line in f.readlines())

def load_seen_ids_from_output(output_file, format_type):
    """Load seen IDs from existing output file"""
    seen_ids = set()
    
    if not os.path.exists(output_file):
        return seen_ids
    
    try:
        if format_type == "csv":
            with open(output_file, 'r', encoding='utf-8-sig') as f:  # Handle BOM
                reader = csv.DictReader(f)
                for row in reader:
                    # Clean up any BOM or whitespace issues in keys
                    for key, value in row.items():
                        clean_key = key.strip().lstrip('\ufeff') if key else 'id'
                        if clean_key == 'id' and value:
                            seen_ids.add(value)
                            break
        elif format_type == "json":
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data:
                    if 'id' in item:
                        seen_ids.add(item['id'])
    except Exception as e:
        print(f"Warning: Could not load existing IDs from {output_file}: {e}")
    
    return seen_ids

def save_seen_ids(filepath, seen_ids):
    with open(filepath, "w") as f:
        for _id in seen_ids:
            f.write(f"{_id}\n")

def append_to_log(file, url):
    with open(file, "a", encoding="utf-8") as f:
        f.write(f"{url}\n")

def convert_csv_to_json(input_file, output_file):
    """Convert CSV file to JSON format"""
    try:
        with open(input_file, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            data = list(reader)
        
        with open(output_file, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=2, ensure_ascii=False)
        
        print(f"Successfully converted {input_file} to {output_file}")
        print(f"Converted {len(data)} items")
        return True
    except Exception as e:
        print(f"Error converting CSV to JSON: {e}")
        return False

def convert_json_to_csv(input_file, output_file):
    """Convert JSON file to CSV format"""
    try:
        with open(input_file, 'r', encoding='utf-8') as jsonfile:
            data = json.load(jsonfile)
        
        if not data:
            print("No data found in JSON file")
            return False
        
        # Get fieldnames from the first item
        fieldnames = data[0].keys() if data else ["id", "title", "url"]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        
        print(f"Successfully converted {input_file} to {output_file}")
        print(f"Converted {len(data)} items")
        return True
    except Exception as e:
        print(f"Error converting JSON to CSV: {e}")
        return False

def handle_convert(args):
    """Handle the convert subcommand"""
    input_file = args.input
    output_file = args.output
    
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' does not exist")
        return
    
    # Determine conversion direction based on file extensions
    input_ext = os.path.splitext(input_file)[1].lower()
    output_ext = os.path.splitext(output_file)[1].lower()
    
    if input_ext == '.csv' and output_ext == '.json':
        convert_csv_to_json(input_file, output_file)
    elif input_ext == '.json' and output_ext == '.csv':
        convert_json_to_csv(input_file, output_file)
    else:
        print(f"Error: Unsupported conversion from {input_ext} to {output_ext}")
        print("Supported conversions: .csv to .json, .json to .csv")

def handle_scrape(args):
    """Handle the scrape subcommand"""
    output_file = f"{args.output}.{args.format}"
    seen_ids_file = f"{args.output}_seen_ids.txt"
    debug_log_file = f"{args.output}_debug_urls.txt"

    # Process date range arguments
    date_start = None
    date_end = None
    if args.date_start:
        date_start = date_to_timestamp(args.date_start)
        if date_start is None:
            return
    if args.date_end:
        date_end = date_to_timestamp(args.date_end)
        if date_end is None:
            return

    # Validate date range
    if date_start and date_end and date_start > date_end:
        print("Error: Start date must be before end date")
        return

    # Check if we need to auto-split the date range
    if args.auto_split and date_start and date_end:
        return handle_auto_split_scrape(args, date_start, date_end)
    
    # Check if we need to use smart auto-splitting
    if args.auto_smart:
        return handle_smart_auto_split_scrape(args, date_start, date_end)

    # Use single range scraping for normal cases
    return handle_scrape_single_range(args, date_start, date_end)

def handle_auto_split_scrape(args, date_start, date_end):
    """Handle auto-split scraping by breaking date range into monthly chunks"""
    print("Auto-split mode enabled. Breaking date range into monthly chunks...")
    
    start_date_str = timestamp_to_date(date_start)
    end_date_str = timestamp_to_date(date_end)
    
    print(f"Splitting date range {start_date_str} to {end_date_str} into monthly chunks")
    
    monthly_ranges = generate_monthly_ranges(start_date_str, end_date_str)
    
    total_stats = {'total_found': 0, 'added': 0, 'skipped': 0}
    total_items = 0
    
    for i, (month_start_ts, month_end_ts, month_start_str, month_end_str) in enumerate(monthly_ranges):
        print(f"\n=== Processing chunk {i+1}/{len(monthly_ranges)}: {month_start_str} to {month_end_str} ===")
        
        # Estimate items for this range
        estimated = estimate_items_for_range(args.appid, month_start_ts, month_end_ts, args.required_tags, args.excluded_tags)
        print(f"Estimated items in this range: {estimated}")
        
        if estimated > MAX_SAFE_ITEMS:
            print(f"WARNING: Range {month_start_str} to {month_end_str} has {estimated} items, exceeding safe limit.")
            print("Consider manually breaking this range into smaller chunks.")
        
        # Create chunk-specific args
        chunk_args = argparse.Namespace(**vars(args))
        chunk_args.date_start = month_start_str
        chunk_args.date_end = month_end_str
        chunk_args.auto_split = False  # Prevent recursive splitting
        
        # Scrape this chunk
        try:
            handle_scrape(chunk_args)
            print(f"Completed chunk {i+1}/{len(monthly_ranges)}")
        except Exception as e:
            print(f"Error processing chunk {month_start_str} to {month_end_str}: {e}")
            continue
    
    print(f"\n=== Auto-split scraping complete ===")
    print(f"Processed {len(monthly_ranges)} monthly chunks")

def handle_smart_auto_split_scrape(args, date_start, date_end):
    """Handle smart auto-split scraping by checking entry counts and recursively splitting"""
    print("Smart auto-split mode enabled. Analyzing entry counts to determine optimal splitting...")
    
    # Get safe ranges using the intelligent splitting
    safe_ranges = auto_split_by_entries(args.appid, date_start, date_end, args.required_tags, args.excluded_tags)
    
    if safe_ranges is None:
        print("Error: Could not determine safe ranges. Falling back to regular scraping.")
        return handle_scrape_single_range(args, date_start, date_end)
    
    if len(safe_ranges) == 0:
        print("No entries found for the given filters.")
        return
    
    print(f"Split into {len(safe_ranges)} safe range(s) for scraping")
    
    total_stats = {'total_found': 0, 'added': 0, 'skipped': 0}
    
    for i, (range_start_ts, range_end_ts) in enumerate(safe_ranges):
        start_str = timestamp_to_date(range_start_ts) if range_start_ts else "beginning"
        end_str = timestamp_to_date(range_end_ts) if range_end_ts else "end"
        
        print(f"\n=== Processing range {i+1}/{len(safe_ranges)}: {start_str} to {end_str} ===")
        
        # Create range-specific args
        range_args = argparse.Namespace(**vars(args))
        range_args.date_start = start_str if range_start_ts else None
        range_args.date_end = end_str if range_end_ts else None
        range_args.auto_split = False  # Prevent recursive splitting
        range_args.auto_smart = False  # Prevent recursive smart splitting
        
        # Scrape this range
        try:
            handle_scrape_single_range(range_args, range_start_ts, range_end_ts)
            print(f"Completed range {i+1}/{len(safe_ranges)}")
        except Exception as e:
            print(f"Error processing range {start_str} to {end_str}: {e}")
            continue
    
    print(f"\n=== Smart auto-split scraping complete ===")
    print(f"Processed {len(safe_ranges)} optimized ranges")

def handle_scrape_single_range(args, date_start, date_end):
    """Handle scraping for a single date range without auto-splitting"""
    output_file = f"{args.output}.{args.format}"
    seen_ids_file = f"{args.output}_seen_ids.txt"
    debug_log_file = f"{args.output}_debug_urls.txt"

    # Load seen IDs from output file (primary source of truth)
    output_seen_ids = load_seen_ids_from_output(output_file, args.format)
    
    # Load seen IDs from seen_ids file (secondary cache)
    file_seen_ids = load_seen_ids(seen_ids_file)
    
    # Check for discrepancies and synchronize
    if output_seen_ids != file_seen_ids:
        print("Detected discrepancy between output file and seen_ids file. Synchronizing...")
        
        # Items in seen_ids file but not in output file (consider these as not really seen)
        orphaned_ids = file_seen_ids - output_seen_ids
        if orphaned_ids:
            print(f"Found {len(orphaned_ids)} IDs in seen_ids file that are not in output file. These will be re-processed.")
            print(f"Sample orphaned IDs: {list(orphaned_ids)[:5]}{'...' if len(orphaned_ids) > 5 else ''}")
        
        # Items in output file but not in seen_ids file (add these to seen_ids)
        missing_ids = output_seen_ids - file_seen_ids
        if missing_ids:
            print(f"Found {len(missing_ids)} IDs in output file that are missing from seen_ids file. Adding them.")
            print(f"Sample missing IDs: {list(missing_ids)[:5]}{'...' if len(missing_ids) > 5 else ''}")
        
        # Synchronize: use output file as source of truth
        seen_ids = output_seen_ids.copy()
        save_seen_ids(seen_ids_file, seen_ids)
        print("Seen_ids file synchronized with output file.")
    else:
        # No discrepancy, use the output file IDs as the authoritative set
        seen_ids = output_seen_ids.copy()
        if seen_ids:
            print("Output file and seen_ids file are synchronized.")
    
    if output_seen_ids:
        print(f"Loaded {len(output_seen_ids)} existing IDs from {output_file}")
    
    stats = {'total_found': 0, 'added': 0, 'skipped': 0}
    all_items = []

    # Determine range
    start_page = args.start_page
    end_page = args.end_page or get_max_page(args.appid, date_start, date_end, args.required_tags, args.excluded_tags)

    if end_page is None:
        print("Unable to determine the end page. Exiting.")
        return

    return scrape_pages_range(args, start_page, end_page, date_start, date_end, 
                            seen_ids, stats, all_items, output_file, seen_ids_file, debug_log_file)

def scrape_pages_range(args, start_page, end_page, date_start, date_end, seen_ids, stats, all_items, output_file, seen_ids_file, debug_log_file):
    """Scrape a specific range of pages with given filters"""
    
    print(f"Scraping Steam Workshop for App ID {args.appid} from page {start_page} to {end_page}")
    print(f"Output: {output_file} ({args.format})")
    print(f"Using up to {MAX_CONCURRENT_PAGES} concurrent page requests")
    
    if date_start or date_end:
        start_str = timestamp_to_date(date_start) if date_start else "beginning"
        end_str = timestamp_to_date(date_end) if date_end else "end"
        print(f"Date range filter: {start_str} to {end_str}")
    
    if args.required_tags:
        print(f"Required tags: {', '.join(args.required_tags)}")
    
    if args.excluded_tags:
        print(f"Excluded tags: {', '.join(args.excluded_tags)}")
    
    if args.force:
        print("Force mode enabled: Will not stop early when fewer than 30 items are found per page")

    total_pages = end_page - start_page + 1
    
    # Thread-safe locks for shared data
    seen_ids_lock = threading.Lock()
    stats_lock = threading.Lock()
    
    try:
        # Create progress bar
        with tqdm(total=total_pages, desc="Scraping pages", unit="page") as pbar:
            pages_to_process = list(range(start_page, end_page + 1))
            early_termination = False
            
            # Process pages in batches of MAX_CONCURRENT_PAGES
            for i in range(0, len(pages_to_process), MAX_CONCURRENT_PAGES):
                if early_termination:
                    break
                    
                batch_pages = pages_to_process[i:i + MAX_CONCURRENT_PAGES]
                batch_items = []
                
                # Fetch pages concurrently
                with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_PAGES, len(batch_pages))) as executor:
                    # Submit all page fetch tasks
                    future_to_page = {
                        executor.submit(fetch_page, args.appid, page, date_start, date_end, args.required_tags, args.excluded_tags): page 
                        for page in batch_pages
                    }
                    
                    # Process completed requests
                    for future in as_completed(future_to_page):
                        page_num = future_to_page[future]
                        
                        try:
                            page_num, response, url = future.result()
                            append_to_log(debug_log_file, url)
                            
                            if response is None or not response.ok:
                                tqdm.write(f"Failed to fetch page {page_num} (HTTP {response.status_code if response else 'Request failed'})")
                                continue

                            new_items = parse_items_thread_safe(
                                response.text, page_num, seen_ids_lock, seen_ids, stats_lock, stats
                            )
                            
                            if new_items:
                                batch_items.extend(new_items)
                                
                                # Check for early termination only if end_page wasn't user-set and force is not enabled
                                if args.end_page is None and not args.force and len(new_items) < ITEMS_PER_PAGE:
                                    tqdm.write(f"Page {page_num}: Fewer than 30 items found. Marking for early termination.")
                                    early_termination = True
                            else:
                                tqdm.write(f"No new items found on page {page_num}")
                            
                            # Update progress bar
                            pbar.update(1)
                            with stats_lock:
                                pbar.set_postfix(found=stats['total_found'], added=stats['added'], skipped=stats['skipped'])
                                
                        except Exception as e:
                            tqdm.write(f"Error processing page {page_num}: {e}")
                            pbar.update(1)
                
                # Add batch items to all_items
                if batch_items:
                    all_items.extend(batch_items)
                
                # Brief delay between batches to be respectful
                if not early_termination and i + MAX_CONCURRENT_PAGES < len(pages_to_process):
                    time.sleep(1.0)
            
            if early_termination:
                tqdm.write("Early termination triggered. Use --force to disable early termination and continue scraping.")

    except KeyboardInterrupt:
        print("\nInterrupted by user. Saving progress...")

    finally:
        if all_items:
            # Save new items to output file
            print(f"Saving {len(all_items)} new items...")
            if args.format == "csv":
                save_to_csv(all_items, output_file)
            else:
                save_to_json(all_items, output_file)

            # Update seen_ids file to match the current state
            final_seen_ids = load_seen_ids_from_output(output_file, args.format)
            save_seen_ids(seen_ids_file, final_seen_ids)
        else:
            print("No new items found to save.")

        print("\n==== Summary ====")
        print(f"Pages processed: {total_pages}")
        print(f"Total items found: {stats['total_found']}")
        print(f"New items added: {stats['added']}")
        print(f"Previously seen items skipped: {stats['skipped']}")
        print(f"Output saved to: {output_file}")
        print(f"Seen ID list: {seen_ids_file}")
        print(f"Debug URL log: {debug_log_file}")

def get_total_entries(app_id, date_start=None, date_end=None, required_tags=None, excluded_tags=None):
    """Get the total number of entries from the workshopBrowsePagingInfo div"""
    url = build_url(app_id, 1, date_start, date_end, required_tags, excluded_tags)
    try:
        response = requests.get(url, headers=HEADERS)
        if not response.ok:
            print("Failed to retrieve page 1 for entry count detection.")
            return None

        soup = BeautifulSoup(response.text, "html.parser")
        
        # Check for "No items matching your search criteria were found"
        no_items_div = soup.find("div", {"class": "view_inventory_page inventory_msg_ctn", "id": "no_items"})
        if no_items_div:
            print("No items found for this filter combination.")
            return 0
        
        # Look for the paging info div
        paging_info_div = soup.find("div", class_="workshopBrowsePagingInfo")
        if not paging_info_div:
            print("Pagination info not found.")
            return None
        
        # Parse text like "Showing 44041-44054 of 44,054 entries"
        paging_text = paging_info_div.get_text().strip()
        print(f"Pagination info: {paging_text}")
        
        # Extract total entries using regex
        match = re.search(r'of\s+([\d,]+)\s+entries', paging_text)
        if match:
            total_str = match.group(1).replace(',', '')
            return int(total_str)
        else:
            print(f"Could not parse total entries from: {paging_text}")
            return None
            
    except Exception as e:
        print(f"Error getting total entries: {e}")
        return None

def auto_split_by_entries(app_id, date_start=None, date_end=None, required_tags=None, excluded_tags=None, max_entries=MAX_SAFE_ITEMS):
    """Automatically split date ranges if they exceed the maximum safe entries"""
    total_entries = get_total_entries(app_id, date_start, date_end, required_tags, excluded_tags)
    
    if total_entries is None:
        return None
    
    if total_entries == 0:
        print("No entries found for the given filters.")
        return []
    
    if total_entries <= max_entries:
        print(f"Total entries ({total_entries:,}) is within safe limit ({max_entries:,})")
        return [(date_start, date_end)]
    
    print(f"Total entries ({total_entries:,}) exceeds safe limit ({max_entries:,}). Auto-splitting...")
    
    # If no date range specified, we need to determine a reasonable range
    if date_start is None or date_end is None:
        # Only fall back to Steam Workshop launch date if we actually detected over 50k items without date filters
        # This means we first tried without date constraints and found too many items
        if date_start is None and date_end is None:
            print("No date range specified and over 50k items detected. Using October 2011 (Steam Workshop launch) as fallback range.")
            start_date = datetime(2011, 10, 13)  # Steam Workshop launch date
            # Set end_date to the last day of the start_date's month
            end_date = start_date.replace(day=calendar.monthrange(start_date.year, start_date.month)[1])
        else:
            # If user specified one date but not the other, use reasonable defaults
            if date_start:
                start_date = datetime.fromtimestamp(date_start)
            else:
                start_date = datetime(2011, 10, 13)  # Steam Workshop launch date
            
            if date_end:
                end_date = datetime.fromtimestamp(date_end)
            else:
                # If only start date specified, use end of that month
                end_date = start_date.replace(day=calendar.monthrange(start_date.year, start_date.month)[1])
            
        date_start = int(start_date.timestamp())
        date_end = int(end_date.timestamp())
    
    # Generate date ranges and recursively check each one
    start_date_str = timestamp_to_date(date_start)
    end_date_str = timestamp_to_date(date_end)
    
    # Start with monthly ranges
    monthly_ranges = generate_monthly_ranges(start_date_str, end_date_str)
    safe_ranges = []
    
    for month_start_ts, month_end_ts, month_start_str, month_end_str in monthly_ranges:
        print(f"Checking range: {month_start_str} to {month_end_str}")
        sub_ranges = auto_split_by_entries(app_id, month_start_ts, month_end_ts, required_tags, excluded_tags, max_entries)
        
        if sub_ranges is None:
            # Error occurred, skip this range
            print(f"Error processing range {month_start_str} to {month_end_str}, skipping...")
            continue
        elif len(sub_ranges) == 0:
            # No entries in this range
            print(f"No entries in range {month_start_str} to {month_end_str}")
            continue
        else:
            safe_ranges.extend(sub_ranges)
    
    return safe_ranges

def generate_weekly_ranges(start_date, end_date):
    """Generate weekly date ranges between start_date and end_date"""
    ranges = []
    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
    end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    
    current = start_dt
    while current <= end_dt:
        week_end = current + timedelta(days=6)
        
        # Don't go past the specified end date
        if week_end > end_dt:
            week_end = end_dt
        
        ranges.append((
            int(current.timestamp()),
            int(week_end.timestamp()),
            current.strftime("%Y-%m-%d"),
            week_end.strftime("%Y-%m-%d")
        ))
        
        # Move to next week
        current = week_end + timedelta(days=1)
        if current > end_dt:
            break
    
    return ranges

def generate_daily_ranges(start_date, end_date):
    """Generate daily date ranges between start_date and end_date"""
    ranges = []
    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
    end_dt = datetime.strptime(end_date, "%Y-%m-%d")
    
    current = start_dt
    while current <= end_dt:
        ranges.append((
            int(current.timestamp()),
            int(current.timestamp()) + 86399,  # End of day (23:59:59)
            current.strftime("%Y-%m-%d"),
            current.strftime("%Y-%m-%d")
        ))
        
        current += timedelta(days=1)
    
    return ranges

def estimate_items_for_range(app_id, date_start, date_end, required_tags=None, excluded_tags=None):
    """Estimate the number of items in a date range by checking max pages"""
    max_page = get_max_page(app_id, date_start, date_end, required_tags, excluded_tags)
    if max_page is None:
        return 0
    return min(max_page * ITEMS_PER_PAGE, MAX_SAFE_ITEMS)

def main():
    # Display CPU-based concurrency info at startup
    cpu_count = os.cpu_count() or 1
    print(f"Detected {cpu_count} CPU core(s). Using {MAX_CONCURRENT_PAGES} concurrent page requests.")
    
    parser = argparse.ArgumentParser(description="Steam Workshop Scraper and Converter")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    subparsers.required = True
    
    # Scrape subcommand
    scrape_parser = subparsers.add_parser('scrape', help='Scrape Steam Workshop items')
    scrape_parser.add_argument("appid", type=int, help="Steam App ID to scrape (e.g., 294100 for RimWorld)")
    scrape_parser.add_argument("-o", "--output", type=str, default="workshop_output", help="Output file path (without extension)")
    scrape_parser.add_argument("-f", "--format", choices=["csv", "json"], default="csv", help="Output file format")
    scrape_parser.add_argument("--start-page", type=int, default=1, help="Page number to start scraping from (default: 1)")
    scrape_parser.add_argument("--end-page", type=int, help="Page number to stop scraping (inclusive). If not set, auto-detected from workshop.")
    scrape_parser.add_argument("--force", action="store_true", help="Force scraping through all pages without early termination when fewer than 30 items are found")
    
    # Date range filtering
    scrape_parser.add_argument("--date-start", type=str, help="Start date for filtering (YYYY-MM-DD format, e.g., 2015-01-01)")
    scrape_parser.add_argument("--date-end", type=str, help="End date for filtering (YYYY-MM-DD format, e.g., 2015-01-31)")
    scrape_parser.add_argument("--auto-split", action="store_true", help="Automatically split large date ranges into monthly chunks to avoid Steam's pagination limit")
    scrape_parser.add_argument("--auto-smart", action="store_true", help="Intelligently auto-split based on actual entry counts, recursively narrowing down to safe ranges")
    
    # Tag filtering
    scrape_parser.add_argument("--required-tags", nargs="+", help="Required tags for filtering (e.g., --required-tags Gamemode Addon)")
    scrape_parser.add_argument("--excluded-tags", nargs="+", help="Excluded tags for filtering (e.g., --excluded-tags Map Weapon)")
    
    scrape_parser.set_defaults(func=handle_scrape)
    
    # Convert subcommand
    convert_parser = subparsers.add_parser('convert', help='Convert between CSV and JSON formats')
    convert_parser.add_argument("input", help="Input file path (CSV or JSON)")
    convert_parser.add_argument("output", help="Output file path (CSV or JSON)")
    convert_parser.set_defaults(func=handle_convert)
    
    # Custom help: show all subparser helps if --help is used at top level
    if len(os.sys.argv) == 2 and os.sys.argv[1] in ("-h", "--help"):
        print(parser.format_help())
        print("\nScrape command options:\n")
        print(scrape_parser.format_help())
        print("\nConvert command options:\n")
        print(convert_parser.format_help())
        return

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
