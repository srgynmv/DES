import struct
from . import constants
from typing import List
from bitarray import bitarray


is_verbose = False


def set_verbose(value: bool):
    """Sets the need for detailed output of each part of the algorithm.

    :param value: True for enable this mode, False otherwise.
    """
    global is_verbose
    is_verbose = value


def __verbose_print(text: str):
    """Prints the text passed to the function if verbose mode is enabled.

    :param text: Human-readable string.
    """
    if is_verbose:
        print(text)


def __format_bitarray_by_block(bits: bitarray, block_size: int = 8) -> str:
    """Separates bits by blocks of length specified by **block_size** parameter.

    :param bits: Bitarray object that will be formatted.
    :param block_size: Block length.
    :return: String containing the blocks separated by space character.
    """
    bits_str = bits.to01()
    return ' '.join(bits_str[idx * block_size: (idx + 1) * block_size] for idx in range(len(bits) // block_size))


def __permute(block: bitarray, table: List[int]) -> bitarray:
    """Utility function to permute any sequence using the permutation table.

    :param block: Sequence that will be permuted.
    :param table: Table used for permutation.
    :return: Permuted sequence.
    """
    table_len = len(table)

    result_block = bitarray(table_len)
    for idx in range(table_len):
        result_block[idx] = block[table[idx]]

    return result_block


def __do_initial_permutation(byte_block: bytes) -> bitarray:
    """Performs the initial permutation using the IP table
    and converts the input byte block to the bitarray object.

    :param byte_block: Block for permutation.
    :return: Permuted block stored in the bitarray object.
    """
    bit_block = bitarray()
    bit_block.frombytes(byte_block)

    assert len(bit_block) == len(constants.ip_table)

    __verbose_print("Original block: " + __format_bitarray_by_block(bit_block))
    return __permute(bit_block, constants.ip_table)


def __transform_b_blocks(b_blocks: bitarray) -> bitarray:
    """Performs the substitution using the substitution boxes.
    Each of the eight S-boxes replaces its 6 input bits with 4 output bits.

    :param b_blocks: Input b-blocks with 48-bit total length.
    :return: Transformed 32-bit b-blocks.
    """
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
    """The Feistel function. For more information see:
    `<https://en.wikipedia.org/wiki/Data_Encryption_Standard#The_Feistel_(F)_function>`_

    :param block_half: Input 32-bit half-block.
    :param key: 48-bit subkey.
    :return: 32-bit permuted block.
    """
    # Expansion
    expanded_block = __permute(block_half, constants.e_table)
    # Key mixing
    b_blocks = expanded_block ^ key
    # Substitution
    transformed_b_blocks = __transform_b_blocks(b_blocks)
    # Permutation
    return __permute(transformed_b_blocks, constants.p_table)


def __feistel_round(in_block: bitarray, key: bitarray) -> bitarray:
    """Performs the one round of DES algorithm.

    :param in_block: Block from previous Feistel round or the initial block.
    :param key: Key for this round.
    :return: Transformed block.
    """
    block_len = len(in_block)
    block_half = block_len // 2
    out_block = bitarray(block_len)

    out_block[:block_half] = in_block[block_half:]
    out_block[block_half:] = in_block[:block_half] ^ __feistel_fn(in_block[block_half:], key)

    __verbose_print("L = " + __format_bitarray_by_block(out_block[:block_half], 4))
    __verbose_print("R = " + __format_bitarray_by_block(out_block[block_half:], 4))

    return out_block


def __process_block(block: bytes, generated_keys: List[bitarray], decode=False) -> bytes:
    """Performs the decoding/encoding for the input 64-bit block.

    :param block: Input block for the following procedure.
    :param generated_keys: List of keys for the Feistel rounds.
    :param decode: Determines decode or encode mode. True for decode, False otherwise.
    :return: Decoded or encoded block.
    """
    assert len(block) == constants.block_size

    try:
        __verbose_print("Input block: " + block.decode('utf-8'))
    except UnicodeDecodeError:
        __verbose_print("Input block: " + str(block))

    bit_block = __do_initial_permutation(block)
    __verbose_print("Shuffled block: " + __format_bitarray_by_block(bit_block))

    range_gen = range(constants.cypher_cycles_count - 1, -1, -1) if decode else range(constants.cypher_cycles_count)

    for idx in range_gen:
        __verbose_print("Round {}:".format(idx + 1))
        bit_block = __feistel_round(bit_block, generated_keys[idx])

    block_half = len(bit_block) // 2
    result_bit_block = bit_block[block_half:] + bit_block[:block_half]

    __verbose_print("Block after rounds: " + __format_bitarray_by_block(result_bit_block))
    result_bit_block = __permute(result_bit_block, constants.ip_table_inv)
    __verbose_print("Block after last permutation: " + __format_bitarray_by_block(result_bit_block))

    return result_bit_block.tobytes()


def __get_initial_key_permutation(key: bytes) -> bitarray:
    """Expands the key if it has the 7 bytes length
     and performs the initial permutation of the source key.

    :param key: Source key for expansion (if needed) and permutation.
    :return: Permuted key.
    """
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
    """Generates keys for each Feistel round.

    :param key: The source key for generation.
    :return: List of keys for each round.
    """
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


def __process_data(data: bytes, key: bytes, decode=False) -> bytes:
    """Splits the data by 8 bytes blocks and generates keys for each cypher cycle.
    Processes data by blocks and merges result to the one byte string.

    :param data: Data to be processed.
    :param key: Key used to process.
    :param decode: Determines decode or encode mode. True for decode, False otherwise.
    :return:
    """
    __verbose_print("Generating keys for rounds...")
    generated_keys = __generate_keys(key)

    result = b''

    block_count = len(data) // constants.block_size
    for block_idx in range(block_count):
        result += __process_block(data[block_idx * constants.block_size:(block_idx + 1) * constants.block_size],
                                  generated_keys, decode)

    return result


def encode(data: bytes, key: bytes) -> bytes:
    """Encodes the data passed in arguments using the key.

    :param data: Data to be encoded.
    :param key: Key used to encode. Must be 7 or 8 bytes length.
    :return: Encoded bytes.
    """
    # Align the data by block_size if needed
    unaligned_bytes_count = len(data) % constants.block_size
    if unaligned_bytes_count:
        data += b'\0' * (constants.block_size - unaligned_bytes_count)

    return __process_data(data, key, False)


def decode(data: bytes, key: bytes, data_in_hex=False) -> bytes:
    """Decodes the data passed in arguments using the key.

    :param data: Data to be decoded.
    :param key: Key used to decode. Must be 7 or 8 bytes length.
    :param data_in_hex: True if data from arguments in the hex format, False otherwise.
    :return: Decoded bytes.
    """
    if data_in_hex:
        data = data.fromhex(data.decode())

    return __process_data(data, key, True)
