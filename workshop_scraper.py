import requests
from bs4 import BeautifulSoup
import time
import csv
import json
import argparse
import os
from tqdm import tqdm

# === CONFIGURATION ===
ITEMS_PER_PAGE = 30
BASE_URL = "https://steamcommunity.com/workshop/browse/"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/114.0.0.0 Safari/537.36"
    )
}

def build_url(app_id, page):
    params = {
        "appid": app_id,
        "section": "readytouseitems",
        "actualsort": "trend",
        "p": page,
        "numperpage": ITEMS_PER_PAGE,
        "browsefilter": "mostrecent",
        "days": 0
    }
    return BASE_URL + "?" + "&".join(f"{k}={v}" for k, v in params.items())

def get_max_page(app_id):
    url = build_url(app_id, 1)
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
    return max_page

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
    end_page = args.end_page or get_max_page(args.appid)

    if end_page is None:
        print("Unable to determine the end page. Exiting.")
        return

    print(f"Scraping Steam Workshop for App ID {args.appid} from page {start_page} to {end_page}")
    print(f"Output: {output_file} ({args.format})")

    total_pages = end_page - start_page + 1
    
    try:
        # Create progress bar
        with tqdm(total=total_pages, desc="Scraping pages", unit="page") as pbar:
            page = start_page
            while page <= end_page:
                url = build_url(args.appid, page)
                append_to_log(debug_log_file, url)
                
                # Update progress bar description with current status
                pbar.set_description(f"Page {page}/{end_page}")
                pbar.set_postfix(found=stats['total_found'], added=stats['added'], skipped=stats['skipped'])

                response = requests.get(url, headers=HEADERS)
                if not response.ok:
                    tqdm.write(f"Failed to fetch page {page} (HTTP {response.status_code})")
                    break

                new_items = parse_items(response.text, seen_ids, stats)
                if new_items:
                    all_items.extend(new_items)

                    # Optional auto-stop if fewer items than expected, and end-page wasn't user-set
                    if args.end_page is None and len(new_items) < ITEMS_PER_PAGE:
                        tqdm.write("Fewer than 30 items on this page. Assuming last page. Stopping early.")
                        pbar.update(1)  # Update for this page
                        break
                elif not new_items:
                    tqdm.write(f"No new items found on page {page}")

                pbar.update(1)  # Update progress bar
                page += 1
                time.sleep(1.5)

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
        print(f"Pages scraped: {page - start_page}")
        print(f"Total items found: {stats['total_found']}")
        print(f"New items added: {stats['added']}")
        print(f"Previously seen items skipped: {stats['skipped']}")
        print(f"Output saved to: {output_file}")
        print(f"Seen ID list: {seen_ids_file}")
        print(f"Debug URL log: {debug_log_file}")

def main():
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
