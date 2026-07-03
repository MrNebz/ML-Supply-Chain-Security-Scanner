import argparse
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mlscan",
        description="Static security scanner for ML model files (.pkl, .onnx, .h5)",
    )
    parser.add_argument("path", help="Path to a model file to scan")
    args = parser.parse_args(argv)

    print(f"Scanning {args.path} ... (scanners not implemented yet)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
