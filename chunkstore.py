#!/usr/bin/env python3
from binascii import hexlify, unhexlify
from os import path, makedirs
from struct import iter_unpack, pack
from sys import argv
import glob

class Chunkstore:
    def __init__(self, filename, depot=None, is_encrypted=None, max_file_size=1 * 1024 * 1024 * 1024):
        filename = filename.replace(".csd", "").replace(".csm", "")
        self.base_filename = filename
        self.depot = depot
        self.is_encrypted = is_encrypted
        self.max_file_size = max_file_size
        self.file_index = 1
        self.chunks = {}
        self._load_existing_files()
        self.chunks_by_csm = {}  # New variable to store chunks by CSM index

    def _load_existing_files(self):
        csm_files = sorted(glob.glob(f"{self.base_filename}_*.csm"))
        num_files = len(csm_files)
        while self.file_index <= num_files:
            self.csmname = f"{self.base_filename}_{self.file_index}.csm"
            self.csdname = f"{self.base_filename}_{self.file_index}.csd"
            print(f"Checking for file: {self.csmname}")  # Debug print
            if not path.exists(self.csmname):
                print(f"File does not exist: {self.csmname}")  # Debug print
                break
            with open(self.csmname, "rb") as csmfile:
                self.csm = csmfile.read()
                if self.csm[:4] != b"SCFS":
                    print("Not a CSM file: " + self.csmname)
                    raise Exception(f"Not a CSM file: {self.csmname}")
                self.depot = int.from_bytes(self.csm[0xc:0x10], byteorder='little', signed=False)
                self.is_encrypted = (self.csm[0x8:0xa] == b'\x03\x00')
                self._unpack()
            print(f"Loaded file: {self.csmname}")  # Debug print
            self.file_index += 1
        self.file_index -= 1
        if self.depot is None or self.is_encrypted is None:
            raise Exception("Need to specify depot or encryption if file doesn't already exist")

    def __repr__(self):
        return f"Depot {self.depot} (encrypted: {self.is_encrypted}, chunks: {len(self.chunks)}) from CSD file {self.csdname}"

    def _unpack(self, unpacker=None):
        if unpacker: assert callable(unpacker)
        with open(self.csmname, "rb") as csmfile:
            csm = csmfile.read()[0x14:]
        for sha, offset, _, length in iter_unpack("<20s Q L L", csm):
            self.chunks[sha] = (offset, length, self.file_index)
            if unpacker:
                unpacker(self, sha, offset, length)
            # Add chunk to chunks_by_csm
            if self.file_index not in self.chunks_by_csm:
                self.chunks_by_csm[self.file_index] = []
            self.chunks_by_csm[self.file_index].append((sha, offset, length))

    def write_csm(self):
        with open(self.csmname, "wb") as csmfile:
            csmfile.write(b"SCFS\x14\x00\x00\x00")
            # if self.is_encrypted:
            #     csmfile.write(b"\x03\x00\x00\x00")
            # else:
            #     csmfile.write(b"\x02\x00\x00\x00")
            ## Same as above, but made single line.
            csmfile.write(b"\x03\x00\x00\x00" if self.is_encrypted else b"\x02\x00\x00\x00")
            csmfile.write(pack("<L L", self.depot, len(self.chunks)))
            csmfile.seek(0, 2)
            # Remove the redundant for loop
            # for sha, (offset, length, file_index) in self.chunks.items():
            #     if file_index == self.file_index:
            #         csmfile.write(sha)
            #         csmfile.write(pack("<Q L L", offset, 0, length))
            # Write chunks in order of offset using chunks_by_csm
            for sha, offset, length in sorted(self.chunks_by_csm[self.file_index], key=lambda x: x[1]):
                csmfile.write(sha)
                csmfile.write(pack("<Q L L", offset, 0, length))

    def get_chunk(self, sha):
        offset, length, file_index = self.chunks[sha]
        csdname = f"{self.base_filename}_{file_index}.csd"
        with open(csdname, "rb") as csdfile:
            csdfile.seek(offset)
            return csdfile.read(length)

    def add_chunk(self, sha, data):
        csdname = f"{self.base_filename}_{self.file_index}.csd"
        if path.exists(csdname):
            with open(csdname, "ab") as csdfile:
                csdfile.seek(0, 2)
                offset = csdfile.tell()
                length = len(data)
                if offset + length > self.max_file_size:
                    self.write_csm()
                    self.file_index += 1
                    self.chunks = {}  # Clear the chunks dictionary
                    self.csmname = f"{self.base_filename}_{self.file_index}.csm"
                    self.csdname = f"{self.base_filename}_{self.file_index}.csd"
                    makedirs(path.dirname(self.csdname), exist_ok=True)
                    self.add_chunk(sha, data)  # Retry adding the chunk to the new file
                else:
                    csdfile.write(data)
                    self.chunks[sha] = (offset, length, self.file_index)
                    # Add chunk to chunks_by_csm
                    if self.file_index not in self.chunks_by_csm:
                        self.chunks_by_csm[self.file_index] = []
                    self.chunks_by_csm[self.file_index].append((sha, offset, length))
        else:
            makedirs(path.dirname(csdname), exist_ok=True)
            with open(csdname, "wb") as csdfile:
                offset = 0
                length = csdfile.write(data)
                self.chunks[sha] = (offset, length, self.file_index)
                # Add chunk to chunks_by_csm
                if self.file_index not in self.chunks_by_csm:
                    self.chunks_by_csm[self.file_index] = []
                self.chunks_by_csm[self.file_index].append((sha, offset, length))

    def get_all_chunks(self):
        return self.chunks

    def get_last_index(self):
        csm_files = sorted(glob.glob(f"{self.base_filename}_*.csm"))
        return len(csm_files)

    def set_current_index(self, index):
        self.file_index = index
        self.csmname = f"{self.base_filename}_{self.file_index}.csm"
        self.csdname = f"{self.base_filename}_{self.file_index}.csd"

if __name__ == "__main__":
    if len(argv) > 1:
        chunkstore = Chunkstore(argv[1])
        print(chunkstore)
