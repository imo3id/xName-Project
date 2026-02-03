import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="Professional Port Scanner")
    parser.add_argument("target", help="الهدف (IP)")
    parser.add_argument("-p", "--ports", default="1-1024", help="نطاق المنافذ")
    parser.add_argument("-t", "--threads", type=int, default=100, help="عدد الخيوط")
    parser.add_argument("-o", "--output", help="اسم ملف التقرير")
    return parser.parse_args()