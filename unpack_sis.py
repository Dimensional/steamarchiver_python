#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify, unhexlify
from os import path, makedirs
from steam.core.crypto import symmetric_encrypt, symmetric_encrypt_with_iv
from steam.core.manifest import DepotManifest
from sys import argv, exit
import signal
from vdf import loads
from chunkstore import Chunkstore
from migration import migration_needed, migrate

def parse_manifest_input(manifest_input):
    """Parse manifest input to get filename and manifest ID"""
    if manifest_input is None:
        return None, None
        
    # Check if it's just a numeric manifest ID (backwards compatibility)
    try:
        manifest_id = int(manifest_input)
        manifest_filename = f"{manifest_id}.manif5"
        return manifest_filename, manifest_id
    except (ValueError, TypeError):
        # It's a filename - extract manifest ID from it
        manifest_filename = f"{manifest_input}.manif5"
        
        # Try to extract manifest ID from filename
        import re
        numbers = re.findall(r'\d+', str(manifest_input))
        if numbers:
            # For workshop files, manifest ID is typically the last number
            manifest_id = int(numbers[-1])
        else:
            raise ValueError(f"Could not extract manifest ID from filename: {manifest_input}")
        
        return manifest_filename, manifest_id

if __name__ == "__main__":
    if migration_needed(): migrate()
    parser = ArgumentParser(description='Unpacks game data chunks from a SteamPipe retail master or game backup.')
    parser.add_argument("target", type=str, help="Path chunkstore to unpack.")
    parser.add_argument("-d", "--depot", type=int, help="Depot ID of the chunkstore.", default=None)
    parser.add_argument("-o", "--output", type=str, help="Output directory for unpacked chunks.", default="chunkstore")
    parser.add_argument("--manifest", type=str, help="Manifest filename (without .manif5 extension) or manifest ID to use for unpacking.", default=None)
    parser.add_argument("-t", "--threads", type=int, default=None, help="Number of threads to use for unpacking.")
    args = parser.parse_args()
    
    if len(argv) == 1:
        parser.print_help()
        exit(1)
    
    depotkey = None
    chunks = None
    if args.manifest:
        chunks = []
        if args.depot is None:
            args.depot = int(path.basename(args.target).split('_')[0])
            
        # Parse manifest input to get filename and ID
        manifest_filename, manifest_id = parse_manifest_input(args.manifest)
        manifest_file = path.join('depot', str(args.depot), 'manifest', manifest_filename)
        
        if not path.exists(manifest_file):
            print(f"Manifest file {manifest_file} not found.")
            print(f"Parsed from input '{args.manifest}' -> filename: '{manifest_filename}', manifest ID: {manifest_id}")
            exit(1)
        with open(manifest_file, "rb") as f:
            manifest = DepotManifest(f.read())
        if manifest.filenames_encrypted:
            depotkey_file = path.join('depot', str(args.depot), f"{args.depot}.depotkey")
            if not path.exists(depotkey_file):
                print(f"Depot key file {depotkey_file} not found.")
                exit(1)
            with open(depotkey_file, "rb") as f:
                depotkey = f.read()
            manifest.decrypt_filenames(depotkey)
        chunks = [hexlify(chunk.sha).decode() for file in manifest.iter_files() for chunk in file.chunks]
        
        chunks = sorted(set(chunks))
    
    try:
        chunkstore = Chunkstore(args.target, depot=args.depot)
    
        depot_id = chunkstore.depot
        output_folder = path.join(args.output, str(depot_id))
        if not path.exists(output_folder):
            print(f"Creating output directory: {output_folder}")
            makedirs(output_folder, exist_ok=True)
    
        chunkstore.unpack(output_folder, chunks=chunks, threads=args.threads)
        print("Unpacking completed successfully.")
    except Exception as e:
        chunkstore.close()
        print(f"Error unpacking chunkstore: {e}")
    except KeyboardInterrupt:
        print("Unpacking interrupted by user.")
        chunkstore.close()
    finally:
        chunkstore.close()