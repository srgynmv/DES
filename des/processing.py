import struct
from . import constants
from typing import List
from bitarray import bitarray


is_verbose = False


def set_verbose(value: bool):
    global is_verbose
    is_verbose = value


def __verbose_print(text: str):
    if is_verbose:
        print(text)


def __format_bitarray_by_block(bits: bitarray, block_size: int = 8) -> str:
    bits_str = bits.to01()
    return ' '.join(bits_str[idx * block_size: (idx + 1) * block_size] for idx in range(len(bits) // block_size))


def __permute(block: bitarray, table: List[int]) -> bitarray:
    table_len = len(table)

    result_block = bitarray(table_len)
    for idx in range(table_len):
        result_block[idx] = block[table[idx]]

    return result_block


def __do_initial_permutation(byte_block: bytes) -> bitarray:
    bit_block = bitarray()
    bit_block.frombytes(byte_block)

    assert len(bit_block) == len(constants.ip_table)

    __verbose_print("Original block: " + __format_bitarray_by_block(bit_block))
    return __permute(bit_block, constants.ip_table)


def __transform_b_blocks(b_blocks: bitarray) -> bitarray:
    transformed_b_blocks = bitarray()

    for idx in range(constants.b_block_count):
        ith_b_block = b_blocks[idx * constants.b_block_size: (idx + 1) * constants.b_block_size]
        s_table_row_idx = ith_b_block[0] * 2 + ith_b_block[-1]
        s_table_col_idx = ith_b_block[1] * 8 + ith_b_block[2] * 4 + ith_b_block[3] * 2 + ith_b_block[4]

        s_value = constants.s_table[idx][s_table_row_idx][s_table_col_idx]
        new_b_block = bitarray()
        new_b_block.frombytes(struct.pack('B', s_value))
        transformed_b_blocks += new_b_block[4:]

    return transformed_b_blocks


def __feistel_fn(block_half: bitarray, key: bitarray) -> bitarray:
    expanded_block = __permute(block_half, constants.e_table)

    b_blocks = expanded_block ^ key
    transformed_b_blocks = __transform_b_blocks(b_blocks)

    return __permute(transformed_b_blocks, constants.p_table)


def __feistel_transform(in_block: bitarray, key: bitarray) -> bitarray:
    block_len = len(in_block)
    block_half = block_len // 2
    out_block = bitarray(block_len)

    out_block[:block_half] = in_block[block_half:]
    out_block[block_half:] = in_block[:block_half] ^ __feistel_fn(in_block[block_half:], key)

    __verbose_print("L = " + __format_bitarray_by_block(out_block[:block_half], 4))
    __verbose_print("R = " + __format_bitarray_by_block(out_block[block_half:], 4))

    return out_block


def __process_block(block: bytes, generated_keys: List[bitarray]) -> bytes:
    assert len(block) == constants.block_size

    __verbose_print("Input block: " + block.decode('utf-8'))
    bit_block = __do_initial_permutation(block)
    __verbose_print("Shuffled block: " + __format_bitarray_by_block(bit_block))

    for idx in range(constants.cypher_cycles_count):
        __verbose_print("Round {}:".format(idx + 1))
        bit_block = __feistel_transform(bit_block, generated_keys[idx])

    block_half = len(bit_block) // 2
    result_bit_block = bit_block[block_half:] + bit_block[:block_half]

    __verbose_print("Block after rounds: " + __format_bitarray_by_block(result_bit_block))
    result_bit_block = __permute(result_bit_block, constants.ip_table_inv)
    __verbose_print("Block after last permutation: " + __format_bitarray_by_block(result_bit_block))

    return result_bit_block.tobytes()


def __get_initial_key_permutation(key: bytes) -> bitarray:
    bit_key = bitarray()
    bit_key.frombytes(key)

    __verbose_print("Original key: " + __format_bitarray_by_block(bit_key))

    need_expand = len(key) == constants.key_size_bytes
    if need_expand:
        expanded_key = bitarray(constants.expanded_key_size_bytes * 8)

        for idx in range(constants.expanded_key_size_bytes):
            expanded_key[idx * 8: (idx + 1) * 8 - 1] = bit_key[idx * 7:(idx + 1) * 7]
            expanded_key[(idx + 1) * 8 - 1] = not bit_key[idx * 7:(idx + 1) * 7].count() % 2
        __verbose_print("Expanded key: " + __format_bitarray_by_block(expanded_key))
    else:
        expanded_key = bit_key

    return __permute(expanded_key, constants.cd_table)


def __generate_keys(key: bytes) -> List[bitarray]:
    assert len(key) in [constants.key_size_bytes, constants.expanded_key_size_bytes]

    result_keys = []

    shuffled_key = __get_initial_key_permutation(key)
    __verbose_print("Shuffled key: " + __format_bitarray_by_block(shuffled_key, 7))

    ci, di = shuffled_key[:constants.c_block_size], shuffled_key[constants.d_block_size:]
    __verbose_print("C0: " + __format_bitarray_by_block(ci, 7))
    __verbose_print("D0: " + __format_bitarray_by_block(di, 7))

    def shift(block, count):
        return block[count:] + block[:count]

    for idx in range(constants.cypher_cycles_count):
        ci, di = shift(ci, constants.cd_offset[idx]), shift(di, constants.cd_offset[idx])

        __verbose_print("")
        __verbose_print("C{}: ".format(idx + 1) + __format_bitarray_by_block(ci, 7))
        __verbose_print("D{}: ".format(idx + 1) + __format_bitarray_by_block(di, 7))

        result_keys.append(__permute(ci + di, constants.ki_table))

        __verbose_print("K{}: ".format(idx + 1) + __format_bitarray_by_block(result_keys[-1], 6))

    return result_keys


def encode(data: bytes, key: bytes) -> bytes:
    # Align the data by block_size if needed
    unaligned_bytes_count = len(data) % constants.block_size
    if unaligned_bytes_count:
        data += b'\0' * (constants.block_size - unaligned_bytes_count)

    __verbose_print("Generating keys for rounds...")
    generated_keys = __generate_keys(key)

    result = b''

    block_count = len(data) // constants.block_size
    for block_idx in range(block_count):
        result += __process_block(data[block_idx * constants.block_size:(block_idx + 1) * constants.block_size],
                                  generated_keys)

    return result


def decode(data: bytes, key: bytes) -> bytes:
    pass  # TODO
