#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify, unhexlify
from os import scandir, makedirs, remove
from os.path import exists, join, isfile
from vdf import dumps
from sys import stderr, argv
from chunkstore import Chunkstore
from steam.core.manifest import DepotManifest
from migration import migration_needed, migrate        

if __name__ == "__main__":
    if migration_needed(): migrate()
    parser = ArgumentParser(description='Pack a SteamPipe backup (.csd/.csm files, and optionally an sku.sis file defining the backup) from individual chunks in the depots/ folder.')
    parser.add_argument("-a", dest="appid", type=int, help="App ID for sku file (if ommitted, no sku will be generated)", nargs="?")
    parser.add_argument("-d", dest="depots", metavar=('depot', 'manifest'), action="append", type=int, help="Depot ID to pack, can be used multiple times. Include a manifest ID too if generating an sku.sis", nargs='+')
    parser.add_argument("-n", dest="name", default="steamarchiver backup", type=str, help="Backup name")
    parser.add_argument("--decrypted", action='store_true', help="Use decrypted chunks to pack backup", dest="decrypted")
    parser.add_argument("--no-update", action='store_true', help="If an existing backup is found, DELETE it instead of updating it", dest="no_update")
    parser.add_argument("--only-manifest", action='store_true', help="Only grab files listed in the manifest", dest="only_manifest")
    parser.add_argument("--compare-manifests", type=int, help="Compare two manifests and only store files found in the new manifest", dest="compare_manifests", default=None)
    # parser.add_argument("--repackage", action='store_true', help="Repackage an existing chunkstore with sorted files", dest="repackage") # Currently unused, might move to separate script.
    parser.add_argument("--destdir", help="Directory to put sis/csm/csd files in", default=".")
    args = parser.parse_args()
    
    if len(argv) == 1:
        parser.print_help()
        exit(1)
    
    if len(args.depots) == 2 and args.only_manifest:
        if args.compare_manifests:
            print("must specify at least 2 manifests to make a diff chunkstore", file=stderr)
            parser.print_usage()
            exit(1)
        else:
            print("must specify at least 1 manifest to make a chunkstore", file=stderr)
            parser.print_usage()
            exit(1)
    
    makedirs(args.destdir, exist_ok=True)
    if args.depots == None:
        print("must specify at least one depot", file=stderr)
        parser.print_usage()
        exit(1)
    sku = {}
    write_sku = False
    if args.appid != None:
        write_sku = True
        sku = {"sku":
                {"name":args.name,
                "disks":"1",
                "disk":"1",
                "backup":"1" if args.decrypted else "0",
                "contenttype":"3",
                "apps":{
                    "0":str(args.appid)
                    },
                "depots":{},
                "manifests":{},
                "chunkstores":{}
              }
        }
        
    missing_chunks = None
    for depot_tuple in args.depots:
        chunks = None
        depot = None
        manifest = None
        chunkfolder = None
        if not exists(args.destdir) and args.destdir is not None:
            makedirs(args.destdir, exist_ok=True)
    
        if args.no_update:
            if exists(args.destdir):
                print("removing existing backup", args.destdir, file=stderr)
                for f in scandir(args.destdir):
                    if f.is_file():
                        remove(f.path)
        
        if len(depot_tuple) == 2:
            depot, manifest = depot_tuple
            depot_folder = join("depot", str(depot))
            chunkfolder = join(depot_folder, "chunk")
            chunks = []
            missing_chunks = []
            if (args.only_manifest):
                current_chunks = []
                depot_key_path = join("depot", str(depot), str(depot) + ".depotkey")
                with open(depot_key_path, "rb") as key_file:
                    depot_key = key_file.read()
                manifest_file = join(depot_folder, "manifest", str(manifest) + ".manif5")
                if not exists(manifest_file):   
                    print("Manifest file does not exist:", manifest_file, file=stderr)
                    exit(1)
                with open(manifest_file, "rb") as f:
                    manifest_data = DepotManifest(f.read())
                    if manifest_data.filenames_encrypted:
                        manifest_data.decrypt_filenames(depot_key)
                    for files in manifest_data.iter_files():
                        if args.decrypted:
                            # If the chunk is decrypted, we need to use the decrypted version
                            for chunk in sorted(files.chunks, key=lambda chunk: chunk.offset):
                                current_chunks.append(hexlify(chunk.sha).decode() + "_decrypted")
                        else:
                            # If the chunk is encrypted, we need to use the encrypted version
                            for chunk in sorted(files.chunks, key=lambda chunk: chunk.offset):
                                current_chunks.append(hexlify(chunk.sha).decode())
                
                if (args.compare_manifests):
                    new_chunks = []
                    new_manifest_file = join(depot_folder, "manifest", str(args.compare_manifests) + ".manif5")
                    if not exists(new_manifest_file):   
                        print("Manifest file does not exist:", new_manifest_file, file=stderr)
                        exit(1)
                    with open(new_manifest_file, "rb") as f:
                        compare_manifest_data = DepotManifest(f.read())
                        if compare_manifest_data.filenames_encrypted:
                            compare_manifest_data.decrypt_filenames(depot_key)
                    for files in compare_manifest_data.iter_files():
                        if args.decrypted:
                            # If the chunk is decrypted, we need to use the decrypted version
                            for chunk in sorted(files.chunks, key=lambda chunk: chunk.offset):
                                new_chunks.append(hexlify(chunk.sha).decode() + "_decrypted")
                        else:
                            # If the chunk is encrypted, we need to use the encrypted version
                            for chunk in sorted(files.chunks, key=lambda chunk: chunk.offset):
                                new_chunks.append(hexlify(chunk.sha).decode())
                
                    # Remove chunks that are already in the original manifest
                if (args.compare_manifests):
                    chunks = [chunk for chunk in new_chunks if chunk not in current_chunks]
                else:
                    chunks = current_chunks
                # Prepend chunkfolder to each chunk name
                # current_chunks = [join(chunkfolder, chunk) for chunk in current_chunks]
                # new_chunks = [join(chunkfolder, chunk) for chunk in new_chunks]
                chunks = [join(chunkfolder, chunk) for chunk in chunks]
                
                # If there are no new chunks, exit
                # Unlikely, but have to have a check for it
                if len(chunks) == 0:
                    print("No new chunks found in the new manifest", file=stderr)
                    exit(1)

                # Verify that all chunks for the manifest are in the designated input folder
                for chunk in chunks:
                    if not exists(chunk):
                        print(f"Missing chunk: {chunk} in {chunkfolder}", file=stderr)
                        missing_chunks.append(chunk)
                if len(missing_chunks) > 0:        
                    print("The following chunks are missing:")
                    for chunk in missing_chunks:
                        print(chunk)
                    exit(1)

            write_sku = True
        else:
            depot = depot_tuple[0]
            chunkfolder = join("depot", str(depot), "chunk")
            chunks = [
                    join(chunkfolder, f.name) for f in scandir(chunkfolder) if f.is_file()
                ]
            if args.decrypted:
                chunks = [chunk for chunk in chunks if chunk.endswith("_decrypted")]
            else:
                chunks = [chunk for chunk in chunks if not chunk.endswith("_decrypted")]
        
        chunks = sorted(set(chunks))
        chunks = sorted(chunks, key=lambda chunk: chunk.lower())
        if write_sku:
            if manifest is None:
                write_sku = False
                print("not generating sku.sis: no manifest specified for depot", depot)
            else:
                sku["sku"]["depots"][len(sku["sku"]["depots"])] = str(depot)
                sku["sku"]["manifests"][str(depot)] = str(manifest) if args.compare_manifests is None else str(args.compare_manifests)
        try:
            chunkstore = Chunkstore(args.destdir, depot, is_encrypted=not args.decrypted)    
            chunkstore.pack(chunks)     
        except KeyboardInterrupt:
            print("aborted by user", file=stderr)
            chunkstore.write_csm()
            chunkstore.close()
            exit(1)
        finally:
            chunkstore.write_csm()
            sizes = chunkstore.get_chunkstore_file_info()
            chunkstore.close()
        if write_sku:
            sku["sku"]["chunkstores"][str(depot)] = {
                str(index): str(file_size) for index, file_size in sizes.items()
            }

    if write_sku:
        with open(args.destdir + "/sku.sis", "w") as skufile:
            skufile.write(dumps(sku, pretty=True, acf=True))
            print("wrote sku.sis")