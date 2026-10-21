"""Bounded, read-only FDT/FIT payload parsing; never executes imported tools."""

from pathlib import Path
import struct

MIB = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def align4(number):
    return (number + 3) & ~3


def stringlist(value):
    value = bytes(value)
    require(0 < len(value) <= 4096 and value.endswith(b"\0"), "Invalid FDT string list")
    result = value[:-1].split(b"\0")
    require(all(result), "Empty FDT string")
    try:
        return [part.decode("ascii") for part in result]
    except UnicodeDecodeError as exc:
        raise ValueError("Non-ASCII FDT string") from exc


def text(value):
    values = stringlist(value)
    require(len(values) == 1, "Expected exactly one FDT string")
    return values[0]


def cell(value):
    require(len(value) == 4, "Expected one big-endian 32-bit FDT cell")
    return struct.unpack(">I", value)[0]


class FDT:
    """Parse a bounded FDT, retaining property ranges for inline FIT data."""

    def __init__(self, data, max_nodes=4096, max_properties=16384):
        require(len(data) >= 40, "Truncated FDT header")
        (
            magic,
            total,
            structure,
            strings,
            reserve,
            version,
            last,
            _,
            strings_size,
            structure_size,
        ) = struct.unpack_from(">10I", data)
        require(magic == 0xD00DFEED, "Invalid FDT magic")
        require(version == 17 and last <= 17, "Unsupported FDT version")
        require(40 <= total <= len(data), "Invalid FDT total size")
        require(structure % 4 == 0 and reserve % 8 == 0, "Unaligned FDT header span")
        spans = [
            (structure, structure + structure_size),
            (strings, strings + strings_size),
        ]
        require(
            all(40 <= a < b <= total for a, b in spans),
            "Invalid FDT structure/string span",
        )
        require(
            spans[0][1] <= spans[1][0] or spans[1][1] <= spans[0][0],
            "Overlapping FDT spans",
        )
        require(40 <= reserve < total, "Invalid FDT reserve span")
        cursor = reserve
        for _ in range(256):
            require(cursor + 16 <= total, "Unterminated FDT memory reserve map")
            pair = struct.unpack_from(">QQ", data, cursor)
            cursor += 16
            if pair == (0, 0):
                break
        else:
            raise ValueError("FDT memory reserve map cap exceeded")
        require(
            all(cursor <= a or b <= reserve for a, b in spans),
            "Overlapping FDT reserve map",
        )
        self.total = total
        self.nodes = {}
        self.ranges = {}
        view = memoryview(data)
        stack = []
        pos, end = structure, structure + structure_size
        properties = 0
        finished = False
        while pos < end:
            require(pos + 4 <= end, "Truncated FDT token")
            token = struct.unpack_from(">I", view, pos)[0]
            pos += 4
            if token == 1:
                nul = data.find(b"\0", pos, end)
                require(nul >= pos and nul - pos <= 255, "Invalid FDT node name")
                try:
                    name = data[pos:nul].decode("ascii")
                except UnicodeDecodeError as exc:
                    raise ValueError("Invalid FDT node name") from exc
                require(
                    "/" not in name and name not in (".", ".."), "Unsafe FDT node name"
                )
                require(
                    (not stack and not name and not self.nodes) or (stack and name),
                    "Invalid FDT root",
                )
                path = (
                    (stack[-1] + "/" + name)
                    if stack and stack[-1] != "/"
                    else "/" + name
                )
                require(path not in self.nodes, "Duplicate FDT node")
                self.nodes[path] = {}
                stack.append(path)
                require(
                    len(stack) <= 64 and len(self.nodes) <= max_nodes,
                    "FDT node/depth cap exceeded",
                )
                pos = align4(nul + 1)
            elif token == 2:
                require(bool(stack), "Unbalanced FDT END_NODE")
                stack.pop()
            elif token == 3:
                require(stack and pos + 8 <= end, "Invalid FDT property token")
                length, offset = struct.unpack_from(">II", view, pos)
                pos += 8
                require(
                    offset < strings_size and pos + length <= end,
                    "Invalid FDT property range",
                )
                start = strings + offset
                nul = data.find(b"\0", start, strings + strings_size)
                require(
                    nul >= start and nul - start <= 255, "Invalid FDT property name"
                )
                name = data[start:nul].decode("ascii")
                require(name and "/" not in name, "Invalid FDT property name")
                require(name not in self.nodes[stack[-1]], "Duplicate FDT property")
                self.nodes[stack[-1]][name] = view[pos : pos + length]
                self.ranges[(stack[-1], name)] = (pos, length)
                properties += 1
                require(properties <= max_properties, "FDT property cap exceeded")
                pos = align4(pos + length)
            elif token == 4:
                continue
            elif token == 9:
                require(not stack and "/" in self.nodes, "Unbalanced FDT END")
                require(not any(view[pos:end]), "Unexpected data after FDT END")
                finished = True
                break
            else:
                raise ValueError("Unknown FDT structure token")
            require(pos <= end, "FDT alignment exceeds structure")
        require(finished, "Missing FDT END token")

    def children(self, path):
        prefix = path.rstrip("/") + "/"
        return [
            p
            for p in self.nodes
            if p.startswith(prefix) and "/" not in p[len(prefix) :]
        ]


def read_fdt(path, cap):
    with Path(path).open("rb") as stream:
        head = stream.read(40)
        require(len(head) == 40, "Truncated FDT header")
        total = struct.unpack_from(">I", head, 4)[0]
        require(40 <= total <= cap, "FDT header byte cap exceeded")
        data = head + stream.read(total - 40)
    require(len(data) == total, "Truncated FDT")
    return FDT(data)
