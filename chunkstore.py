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

class Chunkstore():
    def __init__(self, folder, depot=None, is_encrypted=None, max_file_size=2**30): # Limits to 1GB per file
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
        self.depot = depot
        self.is_encrypted = is_encrypted
        self.max_file_size = max_file_size
        self.files = []
        self.current_csm = None
        self.current_csd = None
        self.current_file_index = 0
        self.current_file_size = 0
        self._thread_local = threading.local()  # Thread-local storage for SQLite connections

        if not path.exists(self.folder):
            raise Exception(f"Folder {self.folder} does not exist")

        # Initialize in-memory SQLite database before loading existing files
        self.conn = sqlite3.connect(":memory:")
        self._init_database(self.conn)

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

    def _write_csm_header(self, csmfile):
        """Writes the common header for a CSM file."""
        csmfile.write(b"SCFS\x14\x00\x00\x00")  # 8 bytes
        if self.is_encrypted is None:
            raise Exception("Encryption status (is_encrypted) must be set before writing CSM headers.")
        csmfile.write(b"\x03\x00\x00\x00" if self.is_encrypted else b"\x02\x00\x00\x00")  # 4 bytes

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

    def write_csm(self, index=None):
        """Writes metadata to the CSM files for all or a specific chunkstore."""
        if index is None:  # Write all CSM files
            for idx, (csd_path, csm_path) in enumerate(self.files, start=1):
                self._write_csm_metadata(idx, csm_path)
        else:  # Write a specific CSM file
            _, csm_path = self.files[index - 1]
            self._write_csm_metadata(index, csm_path)

    def _write_csm_metadata(self, index, csm_path):
        """Writes metadata to a specific CSM file."""
        with open(csm_path, "ab") as csmfile:  # Open in append mode to add metadata
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

    def get_chunk(self, sha_hex):
        """Retrieves the content of a chunk by its SHA1 hash.

        Args:
            sha_hex (str): The SHA1 hash of the chunk in hexadecimal format.

        Returns:
            bytes: The content of the chunk.

        Raises:
            KeyError: If the chunk is not found.
        """
        # Retrieve metadata from SQLite
        cursor = self.conn.execute("SELECT chunkstore_index, offset, length FROM chunks WHERE sha = ?", (sha_hex,))
        result = cursor.fetchone()
        if not result:
            raise KeyError(f"Chunk {sha_hex} not found")
        chunkstore_index, offset, length = result
        csd_path, _ = self.files[chunkstore_index - 1]
        with open(csd_path, "rb") as csdfile:
            csdfile.seek(offset)
            return csdfile.read(length)

    def unpack(self, output_folder):
        """Unpacks all files from the chunkstore into the specified output folder.

        Args:
            output_folder (str): Path to the folder where unpacked files will be saved.

        Raises:
            Exception: If the output folder does not exist and cannot be created.
        """
        if not path.exists(output_folder):
            try:
                os.makedirs(output_folder)
            except Exception as e:
                raise Exception(f"Failed to create output folder: {output_folder}") from e

        # Query all chunks from the SQLite database
        cursor = self.conn.execute("SELECT sha FROM chunks")  # Fixed the SQL query
        for sha_hex, in cursor.fetchall():  # Unpack the single-column result
            # Retrieve the file content using get_chunk
            content = self.get_chunk(sha_hex)  # Pass sha_hex directly to get_chunk

            # Save the file to the output folder
            output_path = path.join(output_folder, sha_hex)
            with open(output_path, "wb") as output_file:
                output_file.write(content)

            print(f"Unpacked file: {output_path}")

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
            if len(sha) != 40 or not all(c in "0123456789abcdef" for c in sha.lower()):
                raise Exception(f"Invalid SHA1 file name: {file_path}")

            with open(file_path, "rb") as file:
                content = file.read()
                self.write_chunk(unhexlify(sha), content)
                print(f"Packed file: {file_path}")

    def close(self):
        """Closes the SQLite connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
        print("SQLite connection closed.")

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

    def validate_chunks(self, chunk_list=None, depot_key=None, threads=None):
        """Validates the integrity of chunks in the chunkstore.

        Args:
            chunk_list (list, optional): List of SHA1 hashes (in hexadecimal) of chunks to validate.
                                         If None, validates all chunks in the chunkstore.
            depot_key (bytes, optional): Key used to decrypt encrypted chunks.
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
            cursor = conn.execute("SELECT sha FROM chunks")
            chunk_list = [row[0] for row in cursor.fetchall()]

        # Use ThreadPoolExecutor to validate chunks in parallel
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_sha = {executor.submit(self._validate_single_chunk, sha_hex, depot_key): sha_hex for sha_hex in chunk_list}
            for future in as_completed(future_to_sha):
                sha_hex, result = future.result()
                validation_results[sha_hex] = result

        return validation_results

    def _validate_single_chunk(self, sha_hex, depot_key):
        """Validates a single chunk.

        Args:
            sha_hex (str): The SHA1 hash of the chunk in hexadecimal format.
            depot_key (bytes, optional): Key used to decrypt encrypted chunks.

        Returns:
            tuple: A tuple containing the SHA1 hash and the validation result (True/False).
        """
        try:
            # Retrieve the chunk content using a thread-local connection
            conn = self._get_thread_local_connection()
            cursor = conn.execute("SELECT chunkstore_index, offset, length FROM chunks WHERE sha = ?", (sha_hex,))
            result = cursor.fetchone()
            if not result:
                return sha_hex, False
            chunkstore_index, offset, length = result
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
