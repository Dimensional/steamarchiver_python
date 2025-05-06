#!/usr/bin/env python3
import sys
import os
import argparse
from chunkstore import Chunkstore
import re
import vdf  # Assuming a VDF library is available for handling VDF files

def get_chunk_files(depot_id, encrypted=True):
    """
    Retrieves all chunk files from the default chunk folder based on the Depot ID.

    Args:
        depot_id (str): The Depot ID to locate the chunk folder.
        encrypted (bool): Whether the chunk files are encrypted.

    Returns:
        list: List of file paths in the chunk folder.

    Raises:
        Exception: If the chunk folder does not exist or contains no files.
    """
    chunk_folder = os.path.join(".", "depot", depot_id, "chunk")
    if not os.path.exists(chunk_folder):
        raise Exception(f"Chunk folder '{chunk_folder}' does not exist.")

    files = [
        os.path.join(chunk_folder, f"{f}_decrypted" if not encrypted else f)
        for f in os.listdir(chunk_folder)
        if os.path.isfile(os.path.join(chunk_folder, f))
    ]

    if not files:
        print(f"No chunk files found in folder '{chunk_folder}'.")
        return None

    return chunk_folder, files

def update_sku_sis(chunkstore_folder, chunkstore):
    """
    Updates the `chunkstores` section in the `sku.sis` file if it exists.

    Args:
        chunkstore_folder (str): Path to the folder where chunkstores are saved.
        chunkstore (Chunkstore): The initialized Chunkstore instance.
    """
    sku_sis_path = os.path.join(chunkstore_folder, "sku.sis")
    if not os.path.exists(sku_sis_path):
        print(f"No 'sku.sis' file found in '{chunkstore_folder}'. Skipping update.")
        return

    print(f"Updating 'sku.sis' file at '{sku_sis_path}'...")
    try:
        with open(sku_sis_path, "r", encoding="utf-8") as file:
            sku_data = vdf.parse(file)

        # Update the `chunkstores` section
        chunkstore_info = chunkstore.get_chunkstore_file_info()
        sku_data["chunkstores"] = {
            str(index): {"size": size} for index, size in chunkstore_info.items()
        }

        # Write the updated VDF back to the file
        with open(sku_sis_path, "w", encoding="utf-8") as file:
            file.write(vdf.dumps(sku_data, pretty=True, acf=True))

        print(f"'sku.sis' file updated successfully.")
    except Exception as e:
        print(f"Failed to update 'sku.sis': {e}")

## Currently the Size argument is hidden in the help output.
## Uncomment the help argument to make it visible in the help output.
def parse_size(size_str):
    """
    Parses a size string (e.g., '500MiB', '2GiB', '500MB', '2GB', '500 MiB', '2 GiB', '50MB') into bytes.

    Args:
        size_str (str): The size string to parse.

    Returns:
        int: The size in bytes.

    Raises:
        ValueError: If the size is invalid or below the minimum allowed size.
    """

    # Match size strings with optional space and unit (e.g., '500 MiB', '2GiB', '50mb')
    match = re.match(r"^(\d+)\s*(mib|mb|gib|gb)$", size_str, re.IGNORECASE)
    if match:
        size_value, unit = match.groups()
        size_value = int(size_value)

        if unit in ("gib", "gb"):
            size = size_value * (1024 ** 3)
        elif unit in ("mib", "mb"):
            size = size_value * (1024 ** 2)
        else:
            size = None
    else:
        size = None

    if size is None:
        print("Invalid size format. Using default size of 500 MiB.")
        size = 500 * (1024 ** 2)
    elif size < 500 * (1024 ** 2):
        print("Size below 500 MiB. Using default size of 500 MiB.")
        size = 500 * (1024 ** 2)
    elif size > 2 * (1024 ** 3):
        print("Size exceeds 2 GiB. Using default size of 2 GiB.")
        size = 2 * (1024 ** 3)
    
    return size

def main(depot_id, chunkstore_folder, use_chunk_folder=False, force=False, max_size=None):
    """
    Repackages chunkstores for the specified chunkstore folder.

    Args:
        depot_id (str): The Depot ID to locate the chunk folder.
        chunkstore_folder (str): Path to the folder where chunkstores are saved.
        use_chunk_folder (bool): Whether to read chunk files from the default chunk folder.
        force (bool): Whether to force repackaging regardless of current state.
        max_size (int): Maximum size (in bytes) for splitting chunkstore files.
    """
    try:
        # Initialize Chunkstore
        print(f"Initializing Chunkstore for folder: {chunkstore_folder}")
        chunkstore = Chunkstore(chunkstore_folder, depot=depot_id)
        encrypted = chunkstore.is_encrypted()
        print(f"Chunkstore is {'encrypted' if encrypted else 'not encrypted'}.")

        chunk_files = None
        path = None
        if use_chunk_folder:
            print(f"Retrieving chunk files for Depot ID: {depot_id}")
            path, chunk_files = get_chunk_files(depot_id, encrypted=encrypted)

        # Repackage or update
        print("Starting repackaging process...")
        chunkstore.repackage_or_update(
            new_files=chunk_files, file_path=path, force=force, max_size=max_size
        )

        # Update `sku.sis` if it exists
        update_sku_sis(chunkstore_folder, chunkstore)

        print("Repackaging completed successfully.")
    except Exception as e:
        print(f"An error occurred during repackaging: {e}")
        chunkstore.close()
    except KeyboardInterrupt:
        print("\nRepackaging process interrupted by user.")
        chunkstore.close()
    finally:
        if 'chunkstore' in locals():
            chunkstore.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Repackage chunkstores for a specified chunkstore folder.")
    parser.add_argument("depot_id", help="Depot ID to locate the chunk folder.")
    parser.add_argument("chunkstore_folder", help="Path to the folder where chunkstores are saved.")
    parser.add_argument(
        "--read-chunks",
        action="store_true",
        help="If specified, reads chunk files from the default chunk folder based on the Depot ID.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        # help="Force repackaging regardless of the current state.",
        help=argparse.SUPPRESS,  # Hide the --force argument from help output
    )
    parser.add_argument(
        "--size",
        type=str,
        # help="Maximum size for splitting chunkstore files (e.g., '500MiB', '2GiB'). Minimum is 500 MiB.",
        help=argparse.SUPPRESS,  # Hide the --size argument from help output
    )

    args = parser.parse_args()

    if not os.path.exists(args.chunkstore_folder):
        print(f"Error: Chunkstore folder '{args.chunkstore_folder}' does not exist.")
        sys.exit(1)

    try:
        max_size_bytes = parse_size(args.size) if args.size else None
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    main(args.depot_id, args.chunkstore_folder, args.read_chunks, args.force, max_size_bytes)
