import sys
from service import HalfOpenScan


def main():
    filename = sys.argv[1]
    instance = HalfOpenScan(filename=filename)
    instance.search()


if __name__ == "__main__":
    main()
