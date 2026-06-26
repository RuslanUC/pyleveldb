from __future__ import annotations
import os
import zlib
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, NamedTuple

from snappy import snappy


class CRC32:
    __slots__ = ("_checksum",)

    def __init__(self) -> None:
        self._checksum = 0

    def update(self, data: bytes) -> None:
        self._checksum = zlib.crc32(data, self._checksum)

    def checksum(self) -> int:
        return self._checksum  # ((self._checksum >> 15) | (self._checksum << 17) + 0xa282ead8) & 0xffffffff


class BlockHandle(NamedTuple):
    offset: int
    size: int

    @classmethod
    def read(cls, fp: BinaryIO) -> BlockHandle:
        offset = read_varint(fp)
        size = read_varint(fp)
        return BlockHandle(offset, size)


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


def iprint(indent: int, text: str) -> None:
    print(f"{' ' * indent}{text}")


def read_ldb_block(fp: BinaryIO, handle: BlockHandle, is_index: bool = False, indent: int = 0) -> None:
    fp.seek(handle.offset + handle.size)
    block_is_compressed = read_int8(fp)
    block_data_crc = read_int32(fp)
    iprint(indent, f"Block is compressed: {block_is_compressed}, checksum: {block_data_crc}")
    fp.seek(handle.offset)
    block_data = fp.read(handle.size)
    if block_is_compressed:
        block_data = snappy.uncompress(block_data)
        iprint(indent, f"Block data: {block_data}")
    else:
        iprint(indent, f"Block data: {block_data}")

    block_actual_size = len(block_data) - 4

    block = BytesIO(block_data)
    block.seek(block_actual_size)
    restart_count = read_int32(block)
    block_actual_size -= restart_count * 4
    block.seek(0)

    iprint(indent, f"Restart count: {restart_count}")

    while block.tell() < block_actual_size:
        shared_key_length = read_varint(block)
        inline_key_length = read_varint(block)
        value_length = read_varint(block)
        inline_key = block.read(inline_key_length)
        value = block.read(value_length)
        if is_index:
            value = BlockHandle.read(BytesIO(value))
        iprint(indent, f"Shared len: {shared_key_length}, inline len: {inline_key_length}, inline: {inline_key}, value: {value}")
        if is_index:
            iprint(indent, "Reading regular block")
            read_ldb_block(fp, value, False, indent + 4)

    block.seek(block_actual_size)
    for restart in range(restart_count):
        restart_value = read_int32(block)
        iprint(indent, f"Restart #{restart}: {restart_value}")


def read_ldb_file(path: Path) -> None:
    with open(path, "rb") as f:
        f.seek(-8, os.SEEK_END)
        magic = f.read(8)
        if magic != b"W\xfb\x80\x8b$uG\xdb":
            raise ValueError(f"Not a leveldb ldb file: {path}")

        f.seek(-48, os.SEEK_END)

        meta_idx_block_handle = BlockHandle.read(f)
        print(f"Meta index block handle: {meta_idx_block_handle}")

        idx_block_handle = BlockHandle.read(f)
        print(f"Index block handle: {idx_block_handle}")

        print("Reading index block")
        read_ldb_block(f, idx_block_handle, True, 2)

        print("Reading meta index block")
        read_ldb_block(f, meta_idx_block_handle, indent=2)

        f.seek(0)



def main() -> None:
    db_path = Path("ldb")

    # manifest_name = get_manifest_name(db_path)
    # read_manifest_file(db_path / manifest_name)

    # read_log_file(db_path / "000044.log")

    read_ldb_file(db_path / "000005.ldb")


if __name__ == "__main__":
    main()
