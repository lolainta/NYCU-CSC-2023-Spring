import os

original_size = os.path.getsize("virus.py")
new_size = 43416

with open("virus.py", "rb") as f:
    original_content = f.read()

with open("infected_cat", "wb") as f:
    f.write(original_content)
    f.write(b"\x00" * (new_size - original_size - 4))
    f.write(b"\xde\xad\xbe\xef")  # Appending the hexadecimal value
