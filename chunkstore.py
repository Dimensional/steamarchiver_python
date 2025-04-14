#!/usr/bin/env python3
from binascii import hexlify, unhexlify
from os import path
from struct import pack, unpack
from sys import argv
import os
import sqlite3
from steam.core.crypto import symmetric_decrypt
from io import BytesIO
from zipfile import BadZipFile, ZipFile
import lzma
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

_LOG = logging.getLogger("Chunkstore")

class Chunkstore():
    def __init__(self, folder, depot=None, depot_key=None, is_encrypted=None, max_file_size=2**30): # Limits to 1GB per file
        """Initializes the Chunkstore class.

        Args:
            folder (str): Path to the folder where chunk files are stored.
            depot (int, optional): Depot ID associated with the chunkstore. Defaults to None.
            is_encrypted (bool, optional): Indicates whether the chunkstore is encrypted. Defaults to None.
            max_file_size (int, optional): Maximum size of each chunk file in bytes. Defaults to 2**30 (1GB).

        Raises:
            Exception: If the specified folder does not exist.
        """
        self.folder = folder
        self.depot_key = depot_key
        self.depot = depot
        self.is_encrypted = is_encrypted
        self.max_file_size = max_file_size
        self.files = []
        self.current_csm = None
        self.current_csd = None
        self.current_file_index = 0
        self.current_file_size = 0

        if not path.exists(self.folder):
            raise Exception(f"Folder {self.folder} does not exist")

        # Initialize in-memory SQLite database before loading existing files
        self.conn = sqlite3.connect(":memory:")
        self._init_database(self.conn)

        self._thread_local = threading.local()  # Thread-local storage for SQLite connections
        self._thread_local_registry = {}  # Shared registry for all thread-local connections
        self._thread_local_lock = threading.Lock()  # Lock for thread-local registry

        # Load existing files after the database is initialized
        self._load_existing_files_to_connection(self.conn)

    def __repr__(self):
        """Returns a string representation of the Chunkstore instance."""
        # Query the total number of chunks
        cursor = self.conn.execute("SELECT COUNT(*) FROM chunks")
        total_chunks = cursor.fetchone()[0]
        return (f"Chunkstore(depot={self.depot}, is_encrypted={self.is_encrypted}, "
                f"max_file_size={self.max_file_size}, chunkstore_files={len(self.files)}, "
                f"total_chunks={total_chunks})")

    def _get_thread_local_connection(self):
        """Gets or creates a thread-local SQLite connection."""
        if not hasattr(self._thread_local, "conn"):
            self._thread_local.conn = sqlite3.connect(":memory:")
            self._init_database(self._thread_local.conn)
            self._load_existing_files_to_connection(self._thread_local.conn)
            # Register the connection in the shared registry
            with self._thread_local_lock:
                self._thread_local_registry[threading.get_ident()] = self._thread_local.conn
        return self._thread_local.conn

    def _init_database(self, conn):
        """Initializes the SQLite database for a given connection."""
        conn.execute("""
            CREATE TABLE chunks (
                sha TEXT PRIMARY KEY,
                chunkstore_index INTEGER,
                offset INTEGER,
                length INTEGER
            )
        """)
        conn.execute("CREATE INDEX idx_sha ON chunks (sha)")

    ### Checks if all existing CSM files have consistent headers and encryption flags.
    ### This method is called when loading existing files to ensure that all files are either encrypted or decrypted.
    def _check_encryption_consistency(self):
        """Checks if all existing CSM files have consistent headers and encryption flags."""
        for _, csm_path in self.files:
            with open(csm_path, "rb") as csmfile:
                header = csmfile.read(4)
                if header != b"SCFS":
                    raise Exception(f"Not a valid CSM file: {csm_path}")
                csmfile.seek(8)  # Skip to the encryption flag
                encryption_flag = csmfile.read(4)
                is_encrypted = encryption_flag == b"\x03\x00\x00\x00"
                if self.is_encrypted is None:
                    self.is_encrypted = is_encrypted
                elif self.is_encrypted != is_encrypted:
                    raise Exception(f"Encryption mismatch in file {csm_path}. "
                                    f"Expected {'encrypted' if self.is_encrypted else 'decrypted'}.")

    ### Loads existing CSD/CSM pairs for the depot and rebuilds the SQLite database.
    ### This method is called when initializing the Chunkstore or when loading existing files.
    ### It checks for encryption consistency and calls _parse_csm_metadata_to_connection to parse metadata.
    ### The metadata is then inserted into the SQLite database.
    def _load_existing_files_to_connection(self, conn):
        """Loads existing CSD/CSM pairs for the depot and rebuilds the SQLite database."""
        for filename in sorted(
            (f for f in os.listdir(self.folder) if f.startswith(f"{self.depot}_") and f.endswith(".csm")),
            key=lambda x: int(x.split("_")[-1].split(".")[0])  # Extract numeric part for sorting
        ):
            base_name = filename.replace(".csm", "")
            csd_path = path.join(self.folder, base_name + ".csd")
            csm_path = path.join(self.folder, base_name + ".csm")
            if path.exists(csd_path):
                # Append the CSD and CSM file paths as a tuple to self.files
                self.files.append((csd_path, csm_path))

        if self.files:
            # Check encryption consistency before parsing metadata
            self._check_encryption_consistency()

            # Parse metadata for each CSM file
            for index, (_, csm_path) in enumerate(self.files, start=1):
                self._parse_csm_metadata_to_connection(csm_path, index, conn)

            # Update the current file index and size
            self.current_file_index = len(self.files)
            self.current_csd, self.current_csm = self.files[-1]
            self.current_file_size = path.getsize(self.current_csd)

    ### Parses metadata from a CSM file and populates the SQLite database for a given connection.
    ### This method is called when loading existing CSM files to rebuild the SQLite database.
    def _parse_csm_metadata_to_connection(self, csm_path, chunkstore_index, conn):
        """Parses metadata from a CSM file and populates the SQLite database for a given connection."""
        with open(csm_path, "rb") as csmfile:
            # Skip the header (12 bytes)
            csmfile.seek(12)

            # Read the chunk count
            depot_id, chunk_count = unpack("<L L", csmfile.read(8))

            # Read each chunk's metadata
            for chunk_index in range(chunk_count): 
                sha = hexlify(csmfile.read(20)).decode()
                offset, _, length = unpack("<Q L L", csmfile.read(16)) 
                # Insert the metadata into the SQLite database
                conn.execute("""
                    INSERT OR REPLACE INTO chunks (sha, chunkstore_index, offset, length)
                    VALUES (?, ?, ?, ?)
                """, (sha, chunkstore_index, offset, length))
            conn.commit()

    ### When creating new CSM files, this method is called to write the common header.
    ### The header consists of a magic number, a version number, and an encryption flag.
    def _write_csm_header(self, csmfile):
        """Writes the common header for a CSM file."""
        csmfile.write(b"SCFS\x14\x00\x00\x00")  # 8 bytes
        if self.is_encrypted is None:
            raise Exception("Encryption status (is_encrypted) must be set before writing CSM headers.")
        csmfile.write(b"\x03\x00\x00\x00" if self.is_encrypted else b"\x02\x00\x00\x00")  # 4 bytes

    ### Creates a new CSD/CSM pair and calls _write_csm_header to write the header to the CSM file.
    ### This method is responsible for creating a new chunkstore file when the current one would exceed the maximum size.
    def _create_new_file(self):
        """Creates a new CSD/CSM pair and writes the header to the CSM file."""
        if self.current_file_index > 0:  # If there is an existing file, finalize its CSM
            self.write_csm(index=self.current_file_index)

        self.current_file_index += 1
        base_name = f"{self.depot}_depotcache_{self.current_file_index}"
        self.current_csd = path.join(self.folder, base_name + ".csd")
        self.current_csm = path.join(self.folder, base_name + ".csm")
        self.files.append((self.current_csd, self.current_csm))
        self.current_file_size = 0
        with open(self.current_csm, "wb") as csmfile:
            self._write_csm_header(csmfile)

    ### Only called from write_csm.
    ### Writes metadata to a specific CSM file for the given chunkstore index.
    ### This method is responsible for writing the chunk metadata to the CSM file.
    def _write_csm_metadata(self, index, csm_path):
        """Writes metadata to a specific CSM file."""
        with open(csm_path, "r+b") as csmfile:  # Open in write mode to overwrite metadata
            csmfile.seek(12)  # Skip the header (12 bytes)
            cursor = self.conn.execute("""
                SELECT sha, offset, length FROM chunks
                WHERE chunkstore_index = ?
                ORDER BY offset
            """, (index,))
            chunks = cursor.fetchall()
            csmfile.write(pack("<L L", self.depot, len(chunks)))  # Chunk count
            for sha, offset, length in chunks:
                csmfile.write(unhexlify(sha))
                csmfile.write(pack("<Q L L", offset, 0, length))

    ### Checks if a file with the given SHA1 already exists in the chunkstore.
    ### This method is used to avoid duplicates when writing chunks, something that shouldn't happen at all.
    def file_exists(self, sha):
        """Checks if a file with the given SHA1 already exists in the chunkstore.

        Args:
            sha (bytes): The SHA1 hash of the file to check.

        Returns:
            bool: True if the file exists, False otherwise.
        """
        sha_hex = hexlify(sha).decode()
        cursor = self.conn.execute("SELECT 1 FROM chunks WHERE sha = ?", (sha_hex,))
        return cursor.fetchone() is not None

    ## Retrieves a chunk from the chunkstore and processes it (decrypts and decompresses).
    ## This method is called by the ThreadPoolExecutor to process chunks in parallel.
    ## It uses the same logic as get_chunk, but processes multiple chunks at once
    ## from a single SQL query result.
    def grab_chunk(self, chunk, depotkey=None):
        sha, chunkstore_index, offset, length = chunk
        csd_path, _ = self.files[chunkstore_index - 1]
        with open(csd_path, "rb") as csdfile:  # Open a new file handle for this thread
            csdfile.seek(offset)
            data = csdfile.read(length)
            return sha, self.process_chunks(sha, data, depotkey)

    ## Reconstructs a file from its chunks and writes it to the specified final file path.
    ## The file is reconstructed in a temporary incomplete file and then renamed to the final file path.
    ## Calls grab_chunks because it uses a list generated from a single sql query
    def get_chunks(self, file, final_file, depotkey=None, threads=None):
        filename = file.filename
        final_file_path = os.path.normpath(final_file)
        incomplete_file_path = os.path.normpath(f"{final_file_path}.incomplete")
        conn = self._get_thread_local_connection()
        sha_list = [hexlify(chunk.sha).decode() for chunk in file.chunks]
        sha_data = {}
        sha_offsets = {hexlify(chunk.sha).decode(): chunk.offset for chunk in file.chunks}
        result = conn.execute(
            "SELECT sha, chunkstore_index, offset, length FROM chunks WHERE sha IN ({})".format(
                ",".join("?" for _ in sha_list)
            ),
            sha_list
        ).fetchall()
        if threads is None:
            threads = max(1, os.cpu_count() - 1)
        else:
            threads = max(1, min(threads, os.cpu_count()))

        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_chunk = {
                    executor.submit(self.grab_chunk, chunk, depotkey)
                    for chunk in result
                }
                for future in as_completed(future_to_chunk):
                    with open(incomplete_file_path, "r+b") as output_file:
                        for future in as_completed(future_to_chunk):
                            sha, content = future.result()
                            output_file.seek(sha_offsets[sha])
                            output_file.write(content)
            os.rename(incomplete_file_path, final_file_path)
            print(f"File reconstructed: {filename}")
        except Exception as e:
            raise Exception(f"Error reconstructing file {filename}: {e}")

    ## Retrieves the content of a chunk by its SHA1 hash from the SQLite database.
    ## If process is True, it will decrypt and decompress the chunk content.
    ## Difference between this and get_chunks is that this method only retrieves a single chunk,
    ## while get_chunks retrieves multiple chunks and reconstructs a file.
    def get_chunk(self, sha_hex, process=False, depot_key=None):
        """Retrieves the content of a chunk by its SHA1 hash.

        Args:
            sha_hex (str): The SHA1 hash of the chunk in hexadecimal format.
            process (bool, optional): Whether to process (decrypt and decompress) the chunk. Defaults to False.
            depot_key (bytes, optional): Key used to decrypt encrypted chunks.

        Returns:
            bytes: The content of the chunk.

        Raises:
            KeyError: If the chunk is not found.
            ValueError: If processing fails or the SHA1 checksum does not match.
        """
        conn = None
        # Retrieve metadata from SQLite
        conn = self._get_thread_local_connection()
        cursor = conn.execute("SELECT chunkstore_index, offset, length FROM chunks WHERE sha = ?", (sha_hex,))
        result = cursor.fetchone()
        if not result:
            raise KeyError(f"Chunk {sha_hex} not found")
        chunkstore_index, offset, length = result
        csd_path, _ = self.files[chunkstore_index - 1]
        with open(csd_path, "rb") as csdfile:  # Open a new file handle for this thread
            csdfile.seek(offset)
            content = csdfile.read(length)
            if process:
                return self.process_chunks(sha_hex, content, depot_key)
            return content

    ## Retrieves the file information (index and size) for each chunkstore file.
    ## This method is called to get the file information for all chunkstore files.
    def get_chunkstore_file_info(self):
        file_info = {}
        for index, (csd_path, _) in enumerate(self.files, start=1):
            file_size = path.getsize(csd_path)
            file_info[index] = file_size
        return file_info

    ## Used to package every loose chunk into the chunkstore for the depot.
    ## This method is called by the pack method to process each file in the input_files list.
    ## It passes each file to the write_chunk method to add it to the chunkstore.
    def pack(self, input_files):
        """Packages the specified list of files into the chunkstore.

        Args:
            input_files (list): List of file paths to be added. File names must be SHA1s.

        Raises:
            Exception: If any file in the list does not exist or has an invalid name.
        """
        
        for file_path in input_files:
            if not path.isfile(file_path):
                raise Exception(f"File {file_path} does not exist or is not a valid file")

            sha = path.basename(file_path)  # Use the file name as the SHA
            if not self.is_encrypted and sha.endswith("_decrypted"):
                sha = sha.replace("_decrypted", "")  # Remove "_decrypted" suffix if not encrypted
            if len(sha) != 40 or not all(c in "0123456789abcdef" for c in sha.lower()):
                raise Exception(f"Invalid SHA1 file name: {file_path}")

            with open(file_path, "rb") as file:
                content = file.read()
                self.write_chunk(unhexlify(sha), content)
                print(f"Packed file: {file_path}")
        
        if self.current_file_index > 0:
            self.write_csm(index=self.current_file_index)

    ### Processes a chunk by decrypting and decompressing it based on its type.
    ### This method is called by the get_chunk and grab_chunk methods to handle chunk processing.
    def process_chunks(self, sha_hex, content, depot_key=None):
        try:
            if self.is_encrypted and depot_key:
                content = symmetric_decrypt(content, depot_key)
                        
            if content[:2] == b'VZ':  # LZMA
                print("Extracting (LZMA) from chunk", sha_hex)
                try:
                    decompressed_size = unpack('<i', content[-6:-2])[0]
                    decompressed = lzma.LZMADecompressor(
                        lzma.FORMAT_RAW,
                        filters=[lzma._decode_filter_properties(lzma.FILTER_LZMA1, content[7:12])]
                    ).decompress(content[12:-10])[:decompressed_size]
                except lzma.LZMAError as e:
                    _LOG.error(f"LZMA decompression failed for chunk {sha_hex}: {e}")
                    raise ValueError(f"LZMA decompression failed for chunk {sha_hex}: {e}")
            elif content[:2] == b'PK':  # Zip
                print("Extracting (Zip) from chunk", sha_hex)
                try:
                    with ZipFile(BytesIO(content)) as zipfile:
                        decompressed = zipfile.read(zipfile.filelist[0])
                except BadZipFile as e:
                    _LOG.error(f"Zip decompression failed for chunk {sha_hex}: {e}")
                    raise ValueError(f"Zip decompression failed for chunk {sha_hex}: {e}")
                except Exception as e:
                    _LOG.error(f"Unknown error during Zip decompression for chunk {sha_hex}: {e}")
                    raise ValueError(f"Unknown error during Zip decompression for chunk {sha_hex}: {e}")
            else:
                _LOG.error(f"Unknown archive type for chunk {sha_hex}: {content[:2].decode()}")
                raise ValueError(f"Unknown archive type for chunk {sha_hex}: {content[:2].decode()}")

            # Calculate the SHA1 hash of the decompressed content
            from hashlib import sha1
            calculated_sha = sha1(decompressed).hexdigest()

            # Compare the calculated SHA1 with the expected SHA1
            if calculated_sha != sha_hex:
                print(f"SHA1 mismatch for chunk {sha_hex}: expected {sha_hex}, got {calculated_sha}")
                raise ValueError(f"SHA1 mismatch for chunk {sha_hex}: expected {sha_hex}, got {calculated_sha}")
                        
            return decompressed
        except Exception as e:
            _LOG.error(f"Error processing chunk {sha_hex}: {e}")
            raise ValueError(f"Error processing chunk {sha_hex}: {e}")

    ### Unpacks a single chunk to the specified output folder.
    ### This method is called by the unpack method to process each chunk in parallel.
    def unpack_chunks(self, sha_hex, chunkstore_index, offset, length, output_folder):
        """Processes and unpacks a single chunk to the specified output folder.

        Args:
            sha_hex (str): The SHA1 hash of the chunk.
            chunkstore_index (int): The index of the chunkstore file.
            offset (int): The offset of the chunk in the file.
            length (int): The length of the chunk.
            output_folder (str): Path to the folder where the chunk will be saved.

        Raises:
            Exception: If there is an error unpacking the chunk.
        """
        if not self.is_encrypted:
            sha_hex += "_decrypted"  # Append "_decrypted" if not encrypted
        csd_path, _ = self.files[chunkstore_index - 1]
        
        output_path = path.join(output_folder, sha_hex)
        if path.exists(output_path):
            return
        
        with open(csd_path, "rb") as csdfile:
            csdfile.seek(offset)
            content = csdfile.read(length)

        # Save the chunk to the output folder
        with open(output_path, "wb") as output_file:
            output_file.write(content)
        print(f"Unpacked file: {output_path}")

    ### Unpacks all files from the chunkstore into the specified output folder using multithreading.
    ### This method is called to process each chunk in parallel using ThreadPoolExecutor.
    def unpack(self, output_folder, threads=None):
        """Unpacks all files from the chunkstore into the specified output folder using multithreading.

        Args:
            output_folder (str): Path to the folder where unpacked files will be saved.
            threads (int, optional): Maximum number of threads to use for parallel processing. Defaults to CPU count.

        Raises:
            Exception: If the output folder does not exist and cannot be created.
        """
        if not path.exists(output_folder):
            try:
                os.makedirs(output_folder)
            except Exception as e:
                raise Exception(f"Failed to create output folder: {output_folder}") from e

        # Query all chunks from the SQLite database
        cursor = self.conn.execute("SELECT sha, chunkstore_index, offset, length FROM chunks")
        # chunks = cursor.fetchall()

        # Determine the number of threads to use
        if threads is None:
            threads = max(1, os.cpu_count() - 1)  # Use all but one CPU core
        else:
            threads = max(1, min(threads, os.cpu_count()))  # Clamp threads between 1 and CPU count

        # Use ThreadPoolExecutor to process chunks in parallel
        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [
                    executor.submit(self.unpack_chunks, sha_hex, chunkstore_index, offset, length, output_folder)
                    for sha_hex, chunkstore_index, offset, length in cursor.fetchall()
                ]
                for future in as_completed(futures):
                    future.result()  # Raise exceptions if any occurred during processing
        except Exception as e:
            raise Exception(f"Error unpacking chunks: {e}")

    ### Responsible for writing a chunk to the chunkstore.
    ### Checks if the file already exists within the SQL Database, skipping if true.
    ### Then it checks if the current CSD will go over the max_file_size, and if so, creates a new file.
    ### It then writes the chunk to the current CSD and inserts metadata into the SQLite database.
    def write_chunk(self, sha, content):
        """Writes a chunk to the appropriate CSD/CSM pair, skipping duplicates.

        Args:
            sha (bytes): The SHA1 hash of the file.
            content (bytes): The file content to write.

        Returns:
            bool: True if the file was added, False if it was skipped.
        """
        if self.file_exists(sha):
            # Skip the file if it already exists
            return False

        # Write a chunk to the appropriate CSD/CSM pair
        if not self.current_csd or self.current_file_size + len(content) > self.max_file_size:
            self._create_new_file()

        with open(self.current_csd, "ab") as csdfile:
            offset = csdfile.tell()
            csdfile.write(content)
            length = len(content)
            self.current_file_size += length

        # Insert metadata into SQLite
        self.conn.execute("""
            INSERT OR REPLACE INTO chunks (sha, chunkstore_index, offset, length)
            VALUES (?, ?, ?, ?)
        """, (hexlify(sha).decode(), self.current_file_index, offset, length))
        self.conn.commit()

        return True

    ### Writes metadata to the CSM files for all or a specific chunkstore.
    ### This method is called when the chunkstore is closed or when a new chunkstore file is created.
    ### It writes the metadata for each chunk in the chunkstore to the corresponding CSM file.
    def write_csm(self, index=None):
        """Writes metadata to the CSM files for all or a specific chunkstore."""
        if index is None:  # Write all CSM files
            for idx, (csd_path, csm_path) in enumerate(self.files, start=1):
                self._write_csm_metadata(idx, csm_path)
        else:  # Write a specific CSM file
            _, csm_path = self.files[index - 1]
            self._write_csm_metadata(index, csm_path)

    ### Closes the SQLite connection and any thread-local connections.
    ### This method is called when the Chunkstore instance is no longer needed.
    def close(self):
        """Closes the SQLite connection and any thread-local connections."""
        # Close the main connection
        if self.conn:
            self.conn.close()
            self.conn = None
            print("Main SQLite connection closed.")

        # Close all thread-local connections
        with self._thread_local_lock:
            for thread_id, conn in self._thread_local_registry.items():
                conn.close()
                print(f"Thread-local SQLite connection for thread {thread_id} closed.")
            self._thread_local_registry.clear()

    ### Exports the SQLite database records to a CSV file for debugging purposes.
    ### This method is called to generate a CSV file containing the chunk metadata:
    ### SHA1, chunkstore index, offset, and length.
    ### The CSV file can be used for debugging or analysis of the chunkstore contents.
    def debug_export_csv(self, output_csv_path):
        """Exports the SQLite database records to a CSV file for debugging purposes.

        Args:
            output_csv_path (str): Path to the output CSV file.

        Raises:
            Exception: If there is an error writing to the CSV file.
        """
        try:
            with open(output_csv_path, "w", newline="") as csvfile:
                csvfile.write("sha,chunkstore_index,offset,length\n")  # Write header
                cursor = self.conn.execute("SELECT sha, chunkstore_index, offset, length FROM chunks")
                for row in cursor.fetchall():
                    csvfile.write(f"{row[0]},{row[1]},{row[2]},{row[3]}\n")
            print(f"Debug export completed: {output_csv_path}")
        except Exception as e:
            raise Exception(f"Failed to export debug CSV: {e}")

    def validate_chunks(self, chunk_list=None, threads=None):
        """Validates the integrity of chunks in the chunkstore.

        Args:
            chunk_list (list, optional): List of SHA1 hashes (in hexadecimal) of chunks to validate.
                                         If None, validates all chunks in the chunkstore.
            threads (int, optional): Maximum number of threads to use for parallel processing.

        Returns:
            dict: A dictionary with chunk SHA1s as keys and validation results (True/False) as values.
        """
        validation_results = {}

        # Determine the number of threads to use
        if threads is None:
            threads = max(1, os.cpu_count() - 1)  # Use all but one CPU core
        else:
            threads = max(1, min(threads, os.cpu_count()))  # Clamp threads between 1 and CPU count

        # If no specific chunks are provided, validate all chunks in the chunkstore
        if chunk_list is None:
            conn = self._get_thread_local_connection()
            cursor = conn.execute("SELECT sha, chunkstore_index, offset, length FROM chunks")  # Fetch all records
            # Use ThreadPoolExecutor to validate chunks in parallel
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_sha = {
                    executor.submit(self._validate_single_chunk, sha_hex, chunkstore_index, offset, length, self.depot_key): sha_hex
                    for sha_hex, chunkstore_index, offset, length in cursor.fetchall()
                }
                for future in as_completed(future_to_sha):
                    sha_hex, result = future.result()
                    validation_results[sha_hex] = result
        
        return validation_results

    ### Functionally identical to process_chunks, but returns the sha name and a true/false value instead of the content.
    ### This method is called by the validate_chunks method to check the integrity of a single chunk.
    def _validate_single_chunk(self, sha_hex, chunkstore_index, offset, length, depot_key):
        """Validates a single chunk.

        Args:
            sha_hex (str): The SHA1 hash of the chunk in hexadecimal format.
            depot_key (bytes, optional): Key used to decrypt encrypted chunks.

        Returns:
            tuple: A tuple containing the SHA1 hash and the validation result (True/False).
        """
        try:
            csd_path, _ = self.files[chunkstore_index - 1]
            with open(csd_path, "rb") as csdfile:
                csdfile.seek(offset)
                content = csdfile.read(length)

            # Decrypt the content if the chunkstore is encrypted
            if self.is_encrypted and depot_key:
                content = symmetric_decrypt(content, depot_key)

            # Decompress the content based on its type
            if content[:2] == b'VZ':  # LZMA
                print("Testing (LZMA) from chunk", sha_hex)
                try:
                    decompressed_size = unpack('<i', content[-6:-2])[0]
                    decompressed = lzma.LZMADecompressor(
                        lzma.FORMAT_RAW,
                        filters=[lzma._decode_filter_properties(lzma.FILTER_LZMA1, content[7:12])]
                    ).decompress(content[12:-10])[:decompressed_size]
                except lzma.LZMAError as e:
                    print(f"\033[31mERROR: LZMA decompression failed\033[0m {e}")
                    return sha_hex, False
            elif content[:2] == b'PK':  # Zip
                print("Testing (Zip) from chunk", sha_hex)
                try:
                    with ZipFile(BytesIO(content)) as zipfile:
                        decompressed = zipfile.read(zipfile.filelist[0])
                except BadZipFile as e:
                    print(f"\033[31mERROR: Zip decompression failed\033[0m {e}")
                    return sha_hex, False
                except Exception as e:
                    print(f"\033[31mERROR: Zip decompression failed\033[0m {e}")
                    return sha_hex, False
            else:
                print(f"\033[31mERROR: unknown archive type\033[0m {content[:2].decode()}")
                return sha_hex, False

            # Calculate the SHA1 hash of the decompressed content
            from hashlib import sha1
            calculated_sha = sha1(decompressed).hexdigest()

            # Compare the calculated SHA1 with the expected SHA1
            return sha_hex, (calculated_sha == sha_hex)
        except Exception as e:
            print(f"Error validating chunk {sha_hex}: {e}")
            return sha_hex, False
        finally:
            # Ensure the thread-local connection is closed after processing
            if hasattr(self._thread_local, "conn"):
                self._thread_local.conn.close()
                del self._thread_local.conn

if __name__ == "__main__":
    if len(argv) > 1:
        chunkstore = None
        try:
            chunkstore = Chunkstore(argv[1])  # Initialize the Chunkstore
            print(chunkstore)  # Perform operations (e.g., print its representation)
        except KeyboardInterrupt:
            print("Processing interrupted by user.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            if chunkstore:
                chunkstore.close()  # Ensure the SQLite connection is closed
