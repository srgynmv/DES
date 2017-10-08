import des


def main():
    sample_key = b'abcdefgg'
    sample_str = b'test1234'

    des.set_verbose(True)
    result = des.encode(sample_str, sample_key)

    print('Result: {}'.format(result.hex()))


if __name__ == '__main__':
    main()
