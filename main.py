import tkinter as tk
from tkinter import scrolledtext, messagebox
# Таблица замен (S-блоки)
data_map = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 14, 3, 11, 6, 8, 12],
]
# Изменение S-блока
def s_box_transform(value):
    result = 0
    for nibble_pos in range(8):
        nibble = (value >> (4 * nibble_pos)) & 0xF
        transformed_nibble = data_map[nibble_pos][nibble]
        result |= transformed_nibble << (4 * nibble_pos)
    return result


def rotate_value(x, shift):
    shifted_left = (x << shift) & 0xFFFFFFFF
    shifted_right = x >> (32 - shift)
    return shifted_left | shifted_right


def encryption_step(a, b, key_part):
    temp_sum = (a + key_part) % 0x100000000
    temp_transformed = s_box_transform(temp_sum)
    temp_rotated = rotate_value(temp_transformed, 11)
    new_b = b ^ temp_rotated
    return new_b, a


def apply_padding(data):
    current_length = len(data)
    pad_length = 8 - (current_length % 8)
    pad_bytes = bytes([pad_length] * pad_length)
    return data + pad_bytes


def remove_padding_bytes(data):
    pad_length = data[-1]
    return data[:-pad_length]


def convert_bytes_to_int(b):
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)


def convert_int_to_bytes(i):
    return bytes([(i & 0xFF), (i >> 8 & 0xFF), (i >> 16 & 0xFF), (i >> 24 & 0xFF)])

# Шифрование блока
def encrypt_block(block, encryption_key):
    a = convert_bytes_to_int(block[:4])
    b = convert_bytes_to_int(block[4:])
    key_segments = [convert_bytes_to_int(encryption_key[i:i+4]) for i in range(0, 32, 4)]
    iteration = 24
    while iteration > 0:
        b, a = encryption_step(a, b, key_segments[(24 - iteration) % 8])
        iteration -= 1
    for step in range(8):
        b, a = encryption_step(a, b, key_segments[7 - step])
    return convert_int_to_bytes(a) + convert_int_to_bytes(b)

# Дешифровка блока
def decrypt_block(cipher_block, decryption_key):
    a = convert_bytes_to_int(cipher_block[:4])
    b = convert_bytes_to_int(cipher_block[4:])
    key_segments = [convert_bytes_to_int(decryption_key[i:i+4]) for i in range(0, 32, 4)]
    for round_step in range(8):
        b, a = encryption_step(a, b, key_segments[round_step])
    iteration = 24
    while iteration > 0:
        b, a = encryption_step(a, b, key_segments[7 - (iteration % 8)])
        iteration -= 1
    return convert_int_to_bytes(a) + convert_int_to_bytes(b)

# Шифрование сообщения
def encrypt_message(data, encryption_key):
    padded_data = apply_padding(data)
    encrypted_output = b''
    block_size = 8
    for index in range(0, len(padded_data), block_size):
        data_block = padded_data[index:index+block_size]
        encrypted_block = encrypt_block(data_block, encryption_key)
        encrypted_output += encrypted_block
    return encrypted_output

# Дешифровка сообщения
def decrypt_message(cipher_data, decryption_key):
    decrypted_output = b''
    block_size = 8
    for index in range(0, len(cipher_data), block_size):
        cipher_block = cipher_data[index:index+block_size]
        decrypted_block = decrypt_block(cipher_block, decryption_key)
        decrypted_output += decrypted_block
    return remove_padding_bytes(decrypted_output)

# Шифрование
def perform_encryption():
    try:
        plaintext = message_input.get("1.0", tk.END).strip().encode()
        encryption_key = key_input.get().encode()
        if len(encryption_key) != 32:
            messagebox.showerror("Ошибочка", "Написано в скобках, - ключ должен быть 32 байта!")
            return
        cipher_output = encrypt_message(plaintext, encryption_key)
        result_display.delete("1.0", tk.END)
        result_display.insert(tk.END, cipher_output.hex())
    except Exception as ex:
        messagebox.showerror("Ошибочка", str(ex))

# Дешифровка
def perform_decryption():
    try:
        cipher_input_hex = message_input.get("1.0", tk.END).strip()
        cipher_input = bytes.fromhex(cipher_input_hex)
        decryption_key = key_input.get().encode()
        if len(decryption_key) != 32:
            messagebox.showerror("Ошибочка", "Написано в скобках, - ключ должен быть 32 байта!")
            return
        decrypted_output = decrypt_message(cipher_input, decryption_key)
        result_display.delete("1.0", tk.END)
        result_display.insert(tk.END, decrypted_output.decode())
    except Exception as ex:
        messagebox.showerror("Ошибочка", str(ex))

# Для копирования
def copy_to_clipboard(widget):
    text = widget.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()

# Основное окно
root = tk.Tk()
root.title("ГОСТ Шифрование")
root.geometry("500x400")

# Ввод
frame1 = tk.Frame(root)
frame1.grid(row=0, column=0, sticky="w", padx=10, pady=5)
tk.Label(frame1, text="Введите Сообщение:").pack(side=tk.LEFT)
copy_button1 = tk.Button(frame1, text="Копировать", command=lambda: copy_to_clipboard(message_input))
copy_button1.pack(side=tk.RIGHT)

message_input = scrolledtext.ScrolledText(root, width=40, height=5)
message_input.grid(row=1, column=0, padx=10, pady=5, sticky="w")

# Ключ
frame2 = tk.Frame(root)
frame2.grid(row=2, column=0, sticky="w", padx=10, pady=5)
tk.Label(frame2, text="Введите Ключ (32 байта):").pack(side=tk.LEFT)
key_input = tk.Entry(frame2, width=40)
key_input.pack(side=tk.RIGHT, padx=10, pady=5)

# Кнопки шифровки и дешифровки
encrypt_btn = tk.Button(root, text="Зашифровать", command=perform_encryption)
encrypt_btn.grid(row=3, column=0, pady=5)
decrypt_btn = tk.Button(root, text="Дешифровать", command=perform_decryption)
decrypt_btn.grid(row=4, column=0, pady=5)

# Вывод
frame3 = tk.Frame(root)
frame3.grid(row=5, column=0, sticky="w", padx=10, pady=5)
tk.Label(frame3, text="Результат:").pack(side=tk.LEFT)
copy_button2 = tk.Button(frame3, text="Копировать", command=lambda: copy_to_clipboard(result_display))
copy_button2.pack(side=tk.RIGHT)

result_display = scrolledtext.ScrolledText(root, width=40, height=5)
result_display.grid(row=6, column=0, padx=10, pady=5, sticky="w")

root.mainloop()