import des
import argparse


def parsed_args():
    parser = argparse.ArgumentParser(description='Encrypt/decrypt using the DES encryption algorithm.')
    parser.add_argument('key', metavar='KEY', type=str, help='a key for encryption/decryption')
    parser.add_argument('text', metavar='TEXT', type=str, help='a string for encryption/decryption')
    parser.add_argument('-e', '--encode', action='store_true', help='encode the text')
    parser.add_argument('-d', '--decode', action='store_true', help='decode the text')
    parser.add_argument('--hex', action='store_true', help='read the encrypted text in hex format')

    return parser.parse_args()


def main():
    args = parsed_args()

    if args.encode:
        print(des.encode(args.text.encode(), args.key.encode()).hex())
    elif args.decode:
        print(des.decode(args.text.encode(), args.key.encode(), args.hex).decode())


if __name__ == '__main__':
    main()
