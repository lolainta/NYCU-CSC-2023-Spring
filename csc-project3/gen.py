import os
from zipfile import ZipFile, ZIP_DEFLATED


def make_cat():
    org = os.path.join("/home/csc2023/", "cat")
    with open(org, "rb") as f:
        content = f.read()
    # print(len(content))
    tmp = "/tmp/cat"
    with ZipFile(tmp, "w", ZIP_DEFLATED) as f:
        f.write(org,arcname='ocat')
    with open(tmp, "rb") as f:
        ccont = f.read()
    # print(len(ccont))
    print(ccont.hex())
    return


def main():
    make_cat()


if __name__ == "__main__":
    main()
