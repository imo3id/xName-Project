import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="Professional Port Scanner")
    parser.add_argument("target", help="target (IP)")
    parser.add_argument("-p", "--ports", default="1-1024", help="To Determine the range of ports")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Thread Number")
    parser.add_argument("-o", "--output", help="Report File name")
    return parser.parse_args()
