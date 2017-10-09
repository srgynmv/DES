import des


def main():
    sample_key = b'abcdefgg'
    sample_str = b'test1234'

    result = des.encode(sample_str, sample_key)
    print('Encoded result: {}'.format(result.hex()))

    result = des.decode(result, sample_key)
    print('Decoded result: {}'.format(result.decode()))


if __name__ == '__main__':
    main()
