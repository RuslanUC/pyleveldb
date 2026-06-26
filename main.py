import os
import zlib
from pathlib import Path
from typing import BinaryIO

from snappy import snappy


class CRC32:
    __slots__ = ("_checksum",)

    def __init__(self) -> None:
        self._checksum = 0

    def update(self, data: bytes) -> None:
        self._checksum = zlib.crc32(data, self._checksum)

    def checksum(self) -> int:
        return self._checksum  # ((self._checksum >> 15) | (self._checksum << 17) + 0xa282ead8) & 0xffffffff


def read_int64(fp: BinaryIO, crc: CRC32 | None = None) -> int:
    data = fp.read(8)
    if len(data) != 8:
        raise ValueError("Unexpected EOF")
    if crc:
        crc.update(data)
    return int.from_bytes(data, "little")


def read_int32(fp: BinaryIO, crc: CRC32 | None = None) -> int:
    data = fp.read(4)
    if len(data) != 4:
        raise ValueError("Unexpected EOF")
    if crc:
        crc.update(data)
    return int.from_bytes(data, "little")


def read_int16(fp: BinaryIO, crc: CRC32 | None = None) -> int:
    data = fp.read(2)
    if len(data) != 2:
        raise ValueError("Unexpected EOF")
    if crc:
        crc.update(data)
    return int.from_bytes(data, "little")


def read_int8(fp: BinaryIO, crc: CRC32 | None = None) -> int:
    data = fp.read(1)
    if len(data) != 1:
        raise ValueError("Unexpected EOF")
    if crc:
        crc.update(data)
    return data[0]


def read_varint(fp: BinaryIO, crc: CRC32 | None = None):
    shift = 0
    result = 0
    while True:
        i = read_int8(fp, crc)
        result |= (i & 0x7f) << shift
        shift += 7
        if not (i & 0x80):
            break

    return result


def read_log_file(path: Path) -> None:
    with open(path, "rb") as f:
        file_size = f.seek(0, os.SEEK_END)
        f.seek(0)

        while f.tell() < file_size:
            crc = CRC32()

            checksum = read_int32(f)
            length = read_int16(f)
            block_type = read_int8(f, crc)

            print(f"Block with type {block_type} of length {length}:")

            start = f.tell()
            while f.tell() < start + length:
                seq = read_int64(f, crc)
                records = read_int32(f, crc)
                print(f"Seq: {seq}")
                print(f"Records: {records}")

                for i in range(records):
                    print(f"Record #{i}:")
                    record_type = read_int8(f, crc)
                    print(f"  Type: {record_type}")
                    key_length = read_varint(f, crc)
                    key = f.read(key_length)
                    crc.update(key)
                    print(f"  Key: {key}")
                    if record_type:
                        value_length = read_varint(f, crc)
                        value = f.read(value_length)
                        crc.update(value)
                        print(f"  Value: {value}")
                    else:
                        print(f"  Value: <deleted>")


def read_manifest_file(path: Path) -> None:
    with open(path, "rb") as f:
        file_size = f.seek(0, os.SEEK_END)
        f.seek(0)

        while f.tell() < file_size:
            crc = CRC32()

            checksum = read_int32(f)
            length = read_int16(f)
            block_type = read_int8(f, crc)

            print(f"Block with type {block_type} of length {length}:")

            start = f.tell()
            while f.tell() < start + length:
                tag = read_varint(f, crc)
                print(f"Field tag: {tag}")
                if tag == 1:
                    string_len = read_varint(f, crc)
                    comparator_name = f.read(string_len)
                    crc.update(comparator_name)
                    print(f"  [Comparator] Comparator name: {comparator_name}")
                elif tag == 2:
                    log_number = read_varint(f, crc)
                    print(f"  [Log number] Log number: {log_number}")
                elif tag == 3:
                    file_number = read_varint(f, crc)
                    print(f"  [Next file number] Next file number: {file_number}")
                elif tag == 4:
                    last_seq = read_varint(f, crc)
                    print(f"  [Last sequence number] Last seq number: {last_seq}")
                elif tag == 5:
                    level = read_varint(f, crc)
                    key_len = read_varint(f, crc)
                    key = f.read(key_len)
                    crc.update(key)
                    print(f"  [Compact pointer] Level: {level}, internal key: {key}")
                elif tag == 6:
                    level = read_varint(f, crc)
                    file_num = read_varint(f, crc)
                    print(f"  [Deleted file] File level: {level}, file number: {file_num}")
                elif tag == 7:
                    level = read_varint(f, crc)
                    file_num = read_varint(f, crc)
                    file_size_ = read_varint(f, crc)

                    smallest_key_len = read_varint(f, crc)
                    smallest_key = f.read(smallest_key_len)
                    crc.update(smallest_key)
                    largest_key_len = read_varint(f, crc)
                    largest_key = f.read(largest_key_len)
                    crc.update(largest_key)

                    print(
                        f"  [New file] Level: {level}, file num: {file_num}, file size: {file_size_}, "
                        f"smallest: {smallest_key}, largest: {largest_key}"
                    )
                elif tag == 9:
                    log_number = read_varint(f, crc)
                    print(f"  [Prev log number] Log number: {log_number}")
                else:
                    raise ValueError(f"Unknown tag: {tag}")


def get_manifest_name(db_path: Path) -> str:
    with open(db_path / "CURRENT") as f:
        file_size = f.seek(0, os.SEEK_END)
        if file_size != 16:
            raise ValueError(f"Invalid leveldb database: expected CURRENT to be 16 bytes, but it's {file_size}")

        f.seek(0)
        manifest_name = f.read(15)

        if f.read() != "\n":
            raise ValueError(f"Invalid leveldb database: expected CURRENT to end with newline")
        if not manifest_name.startswith("MANIFEST-"):
            raise ValueError(f"Invalid leveldb database: expected CURRENT to start with \"MANIFEST-\"")

        print(f"Current manifest: {manifest_name}")
        return manifest_name


def read_ldb_block(fp: BinaryIO, offset: int, size: int) -> None:
    fp.seek(offset + size)
    block_is_compressed = read_int8(fp)
    block_data_crc = read_int32(fp)
    print(f"  Block is compressed: {block_is_compressed}, checksum: {block_data_crc}")
    fp.seek(offset)
    block_data = fp.read(size)
    if block_is_compressed:
        block_data = snappy.uncompress(block_data)
        print(f"  Block data: {block_data}")
    else:
        print(f"  Block data: {block_data}")


def read_ldb_file(path: Path) -> None:
    with open(path, "rb") as f:
        f.seek(-8, os.SEEK_END)
        magic = f.read(8)
        if magic != b"W\xfb\x80\x8b$uG\xdb":
            raise ValueError(f"Not a leveldb ldb file: {path}")

        f.seek(-48, os.SEEK_END)

        meta_idx_block_loc = read_varint(f)
        meta_idx_block_size = read_varint(f)
        print(f"Meta index block location: {meta_idx_block_loc}, size: {meta_idx_block_size}")

        idx_block_loc = read_varint(f)
        idx_block_size = read_varint(f)
        print(f"Index block location: {idx_block_loc}, size: {idx_block_size}")

        print("Reading index block")
        read_ldb_block(f, idx_block_loc, idx_block_size)

        print("Reading meta index block")
        read_ldb_block(f, meta_idx_block_loc, meta_idx_block_size)

        f.seek(0)



def main() -> None:
    db_path = Path("ldb")

    # manifest_name = get_manifest_name(db_path)
    # read_manifest_file(db_path / manifest_name)

    # read_log_file(db_path / "000044.log")

    read_ldb_file(db_path / "000005.ldb")


if __name__ == "__main__":
    main()
