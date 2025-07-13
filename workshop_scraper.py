import requests
from bs4 import BeautifulSoup
import time
import csv
import json
import argparse
import os

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
    write_header = not os.path.exists(filename)
    with open(filename, mode="a", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "title", "url"])
        if write_header:
            writer.writeheader()
        writer.writerows(data)

def save_to_json(data, filename):
    existing = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                existing = []

    existing.extend(data)
    with open(filename, mode="w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

def load_seen_ids(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r") as f:
        return set(line.strip() for line in f.readlines())

def save_seen_ids(filepath, seen_ids):
    with open(filepath, "w") as f:
        for _id in seen_ids:
            f.write(f"{_id}\n")

def append_to_log(file, url):
    with open(file, "a", encoding="utf-8") as f:
        f.write(f"{url}\n")

def main():
    parser = argparse.ArgumentParser(description="Steam Workshop Scraper")
    parser.add_argument("appid", type=int, help="Steam App ID to scrape (e.g., 294100 for RimWorld)")
    parser.add_argument("-o", "--output", type=str, default="workshop_output", help="Output file path (without extension)")
    parser.add_argument("-f", "--format", choices=["csv", "json"], default="csv", help="Output file format")
    parser.add_argument("--start-page", type=int, default=1, help="Page number to start scraping from (default: 1)")
    parser.add_argument("--end-page", type=int, help="Page number to stop scraping (inclusive). If not set, auto-detected from workshop.")
    args = parser.parse_args()

    output_file = f"{args.output}.{args.format}"
    seen_ids_file = f"{args.output}_seen_ids.txt"
    debug_log_file = f"{args.output}_debug_urls.txt"

    seen_ids = load_seen_ids(seen_ids_file)
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

    try:
        page = start_page
        while page <= end_page:
            url = build_url(args.appid, page)
            append_to_log(debug_log_file, url)
            print(f"Fetching page {page}/{end_page}...")

            response = requests.get(url)
            if not response.ok:
                print(f"Failed to fetch page {page} (HTTP {response.status_code})")
                break

            new_items = parse_items(response.text, seen_ids, stats)
            if not new_items:
                print("No new items found on this page.")
            else:
                all_items.extend(new_items)

                # Optional auto-stop if fewer items than expected, and end-page wasn't user-set
                if args.end_page is None and len(new_items) < ITEMS_PER_PAGE:
                    print("Fewer than 30 items on this page. Assuming last page. Stopping early.")
                    break

            all_items.extend(new_items)
            page += 1
            time.sleep(1.5)

    except KeyboardInterrupt:
        print("\nInterrupted by user. Saving progress...")

    finally:
        if all_items:
            if args.format == "csv":
                save_to_csv(all_items, output_file)
            else:
                save_to_json(all_items, output_file)

            save_seen_ids(seen_ids_file, seen_ids)

        print("\n==== Summary ====")
        print(f"Pages scraped: {page - 1 - start_page + 1}")
        print(f"Total items found: {stats['total_found']}")
        print(f"New items added: {stats['added']}")
        print(f"Previously seen items skipped: {stats['skipped']}")
        print(f"Output saved to: {output_file}")
        print(f"Seen ID list: {seen_ids_file}")
        print(f"Debug URL log: {debug_log_file}")

if __name__ == "__main__":
    main()
