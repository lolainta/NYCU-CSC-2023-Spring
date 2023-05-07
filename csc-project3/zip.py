import os
from zipfile import ZipFile, ZIP_DEFLATED


def make_cat():
    org = os.path.join("/home/csc2023/", "cat")
    tmp = "/tmp/cat"
    with ZipFile(tmp, "w", ZIP_DEFLATED) as f:
        f.write(org,arcname='ocat')
    with open(tmp, "rb") as f:
        ccont = f.read()
    print(ccont.hex())

def main():
    make_cat()


if __name__ == "__main__":
    main()
