#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify, unhexlify
from os import path, makedirs
from steam.core.crypto import symmetric_encrypt, symmetric_encrypt_with_iv
from steam.core.manifest import DepotManifest
from sys import argv
from vdf import loads
from chunkstore import Chunkstore
from migration import migration_needed, migrate

if __name__ == "__main__":
    if migration_needed(): migrate()
    parser = ArgumentParser(description='Unpacks game data chunks from a SteamPipe retail master or game backup.')
    parser.add_argument("target", type=str, help="Path chunkstore to unpack.")
    parser.add_argument("-d", "--depot", type=int, help="Depot ID of the chunkstore.", default=None)
    parser.add_argument("-o", "--output", type=str, help="Output directory for unpacked chunks.", default="chunkstore")
    args = parser.parse_args()
    
    try:
        chunkstore = Chunkstore(args.target, depot=args.depot)
    
        depot_id = chunkstore.depot
        output_folder = path.join(args.output, str(depot_id))
        if not path.exists(output_folder):
            print(f"Creating output directory: {output_folder}")
            makedirs(output_folder, exist_ok=True)
    
        chunkstore.unpack(output_folder)
        print("Unpacking completed successfully.")
    except Exception as e:
        chunkstore.close()
        print(f"Error unpacking chunkstore: {e}")
    finally:
        chunkstore.close()