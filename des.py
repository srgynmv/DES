import des
import enum
import base64
import argparse


class ArgumentEnum(enum.Enum):
    def _generate_next_value_(name, start, count, last_values):
        return name

    def __str__(self):
        return self.name

    @classmethod
    def from_string(cls, value):
        try:
            return cls[value]
        except KeyError:
            raise ValueError()


class ProcessingType(ArgumentEnum):
    encode = enum.auto(),
    decode = enum.auto()


class FormatType(ArgumentEnum):
    hex = enum.auto(),
    base64 = enum.auto()

    def encode(self, string: bytes) -> str:
        if self == FormatType.hex:
            return string.hex()
        elif self == FormatType.base64:
            return base64.b64encode(string).decode()

    def decode(self, string: str) -> bytes:
        if self == FormatType.hex:
            return bytes.fromhex(string)
        elif self == FormatType.base64:
            return base64.b64decode(string)


def parsed_args():
    parser = argparse.ArgumentParser(description='Encrypt/decrypt using the DES encryption algorithm.')
    parser.add_argument('key', metavar='KEY', type=str, help='a key for encryption/decryption')
    parser.add_argument('text', metavar='TEXT', type=str, help='a string for encryption/decryption')
    parser.add_argument('-t', '--type', type=ProcessingType.from_string,
                        choices=list(ProcessingType), nargs='?', default=ProcessingType.encode,
                        help='processing type')
    parser.add_argument('-f', '--format', type=FormatType.from_string,
                        choices=list(FormatType), nargs='?', default=FormatType.hex,
                        help='determines the output format for encoding or the input format for decoding')

    return parser.parse_args()


def main():
    args = parsed_args()

    if args.type == ProcessingType.encode:
        result = des.encode(args.text.encode(), args.key.encode())
        print(args.format.encode(result))

    elif args.type == ProcessingType.decode:
        input_text = args.format.decode(args.text)
        print(des.decode(input_text, args.key.encode()).decode())


if __name__ == '__main__':
    main()
