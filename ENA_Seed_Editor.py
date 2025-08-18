import tkinter as tk
from tkinter import filedialog, ttk, PhotoImage
import os
import sys
import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import configparser
import keyboard

VERSION_NUMBER = "v1.0.1"

KEY = b"n7cRY4o5XFbjs44hL68AzDA4hGjAJRhJ"
IV = b"RrbEcXchnNDt4d5r"
CONFIG_FILE = "config.ini"
MAX_FOLDER_NAME_CHARS = 70

save_data = {}
hotkey_keys = {}
hotkey_ids = {}
selected_folder = ""
current_save_index = 0

save_files = ["save_0.dat", "save_1.dat", "save_2.dat"]
slot_names = ["Save 0", "Save 1", "Save 2"]
button_actions = ["refresh", "change_seed", "wipe_data", "copy_seed", "select_folder", "slot_0", "slot_1", "slot_2"]

# Fresh template for wiping
fresh_template = {
    "saveHash": 0,
    "metadata": {
        "createTime": "",
        "savedTime": ""
    },
    "timer": {
        "totalGameTime": 0.0,
        "totalGameTimeRealtime": 0.0,
        "totalPhysicsTicks": 0
    },
    "gameState": {
        "hasSavedSceneEntry": False,
        "savedSceneName": "Outworld",
        "savedSceneEntrance": "",
        "milestoneProgress": 0
    },
    "inventory": {"lastEquipmentIndex": 0, "Lookup": {}},
    "questData": {"quests": {}},
    "genericData": {"data": {}},
    "dialogueData": {"data": {}},
    "inputGuide": {"data": {}},
    "nodeTraversalHistory": {"historyLookup": {}},
    "dialogueLog": {"entries": []}
}

def decrypt_save_file(file_path):
    with open(file_path, "rb") as f:
        encrypted = f.read()
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return json.loads(decrypted.decode("utf-8"))

def encrypt_save_file(file_path, data):
    text = json.dumps(data, separators=(',', ':'))
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted = cipher.encrypt(pad(text.encode("utf-8"), AES.block_size))
    with open(file_path, "wb") as f:
        f.write(encrypted)

def load_save(index):
    if selected_folder == "":
        set_status(f"No folder selected! ❌", False)
        return

    global save_data, current_save_index
    current_save_index = index

    file_path = os.path.join(selected_folder, save_files[index])
    if os.path.exists(file_path):
        save_data = decrypt_save_file(file_path)
        seed_entry.delete(0, tk.END)
        seed_entry.insert(0, str(save_data.get("saveHash", "")))
        set_status(f"{save_files[index]} loaded successfully ✅", True)
    else:
        seed_entry.delete(0, tk.END)
        set_status(f"{save_files[index]} not found ❌", False)

def select_folder():
    global selected_folder
    folder = filedialog.askdirectory()
    if folder:
        selected_folder = folder
        label_text = f"Selected Folder:\n{selected_folder}"
        if len(label_text) > MAX_FOLDER_NAME_CHARS:
            label_text = label_text[:MAX_FOLDER_NAME_CHARS] + "..."
        folder_label.config(text=label_text)
        save_config_folder()
        load_save(save_selector.current())

def update_seed():
    if selected_folder == "":
        set_status(f"No folder selected! ❌", False)
        return
    try:
        new_seed = int(seed_entry.get())
        save_data["saveHash"] = new_seed
        file_path = os.path.join(selected_folder, save_files[current_save_index])
        encrypt_save_file(file_path, save_data)
        set_status("Seed updated successfully ✅", True)
    except Exception as e:
        set_status(f"Error: {str(e)}", False)

def wipe_and_set_seed():
    if selected_folder == "":
        set_status(f"No folder selected! ❌", False)
        return
    try:
        new_seed = int(seed_entry.get())
        now = datetime.utcnow().isoformat() + "0+00:00" # "0" is added before the "+" to account for the game's 7 digit microsecond precision that python is incapable of
        fresh = json.loads(json.dumps(fresh_template))
        fresh["saveHash"] = new_seed
        fresh["metadata"]["createTime"] = now
        fresh["metadata"]["savedTime"] = now

        file_path = os.path.join(selected_folder, save_files[current_save_index])
        encrypt_save_file(file_path, fresh)
        load_save(current_save_index)
        set_status(f"Fresh save with seed created in {save_files[current_save_index]} ✅", True)
    except Exception as e:
        set_status(f"Error: {str(e)}", False)

def copy_seed():
    root.clipboard_clear()
    root.clipboard_append(seed_entry.get())
    set_status("Seed copied to clipboard 📋", True)

def save_config_folder():
    config = configparser.ConfigParser()

    # Store the last folder
    config["Settings"] = {"last_folder": selected_folder}

    config["Hotkeys"] = hotkey_keys

    # Write the config to the file
    with open(CONFIG_FILE, "w") as configfile:
        config.write(configfile)

def create_config():
    config = configparser.ConfigParser()

    # Store the last folder
    config["Settings"] = {"last_folder": selected_folder}

    # Store dynamic hotkeys as empty by default
    config["Hotkeys"] = {action: "" for action in button_actions}

    # Write the config to the file
    with open(CONFIG_FILE, "w") as configfile:
        config.write(configfile)

# Function to load config and hotkeys
def load_config():
    global selected_folder, hotkey_keys, hotkey_ids

    if os.path.exists(CONFIG_FILE):
        try:
            config = configparser.ConfigParser()
            config.read(CONFIG_FILE)

            # Load the last selected folder
            selected_folder = config.get("Settings", "last_folder", fallback="")
            if selected_folder and os.path.isdir(selected_folder):
                label_text = f"Selected Folder:\n{selected_folder}"
                if len(label_text) > MAX_FOLDER_NAME_CHARS:
                    label_text = label_text[:MAX_FOLDER_NAME_CHARS] + "..."
                folder_label.config(text=label_text)
                load_save(current_save_index)
            
            hotkey_ids_copy = hotkey_ids.copy()

            for action, id in hotkey_ids_copy.items():
                keyboard.remove_hotkey(id)
                hotkey_ids.pop(action, None)

            # Load hotkeys from the config
            hotkey_keys = {key: config.get("Hotkeys", key, fallback="") for key in button_actions}
                
            for action, button in hotkey_keys.items():
                if button:
                    hotkey_ids[action] = keyboard.add_hotkey(button, bind_action(action))

            return True
        except Exception as e:
            set_status(f"Internal Error: {str(e)}", False)
            return False
    else:
        create_config()
        return True

def set_status(message, success=True):
    color = "green" if success else "red"
    status_label.config(text=message, fg=color)

# Get the correct path for the icon
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def bind_action(action_name):
    return lambda: globals()[f"{action_name}_button"].invoke()

def refresh_config():
    if load_config():
        set_status("Successfully reloaded ✅", True)

def load_save_hotkey(index):
    load_save(index)
    # Manually set dropdown text
    save_selector.set(slot_names[index])


# Create config if it doesn't exist

if not os.path.exists(CONFIG_FILE):
    create_config()

# GUI Setup

root = tk.Tk()
root.title(f"ENA: Dream BBQ / Seed Editor ({VERSION_NUMBER})")
root.geometry("500x180")
root.resizable(False, False)

# Use resource_path to get the PNG icon for both compiled and non-compiled
icon_path = resource_path("ena_dbbq.png")
# Set the icon using PhotoImage
icon_image = PhotoImage(file=icon_path)
root.iconphoto(False, icon_image)

# Top: Folder selection
folder_frame = tk.Frame(root)
folder_frame.pack(pady=(10, 2), anchor="w")

select_folder_button = tk.Button(folder_frame, text="📁 Select Save Folder", command=select_folder)
select_folder_button.pack(side="left", padx=5)

folder_label = tk.Label(folder_frame, text="No folder selected", anchor="w", justify="left", wraplength=500)
folder_label.pack(side="left")

middle_frame = tk.Frame(root)
middle_frame.pack(pady=(5, 0))

refresh_button = tk.Button(middle_frame, text="🔄 Refresh", command=lambda: refresh_config())
refresh_button.grid(row=0, column=0, padx=(0, 10), pady=0)

save_selector = ttk.Combobox(middle_frame, values=slot_names, state="readonly", width=7)
save_selector.current(0)
save_selector.grid(row=0, column=1, padx=5, pady=0)
save_selector.bind("<<ComboboxSelected>>", lambda e: load_save(save_selector.current()))

seed_entry = tk.Entry(middle_frame, font=("Segoe UI", 12), width=20, justify="center")
seed_entry.grid(row=0, column=2, padx=5, pady=0)

button_frame = tk.Frame(middle_frame)
button_frame.grid(row=0, column=3, padx=5, pady=0)

change_seed_button = tk.Button(button_frame, text="Change Seed", command=update_seed, width=15)
change_seed_button.pack(pady=2)

wipe_data_button = tk.Button(button_frame, text="Fresh Save with Seed", command=wipe_and_set_seed, width=15)
wipe_data_button.pack(pady=2)

status_frame = tk.Frame(root)
status_frame.pack(pady=0)

copy_seed_button = tk.Button(status_frame, text="📋 Copy Seed", command=copy_seed)
copy_seed_button.grid(row=0, column=0, pady=0)

status_label = tk.Label(status_frame, text="", font=("Segoe UI", 10))
status_label.grid(row=1, column=0, pady=0)

# Hidden slot selector buttons

slot_0_button = tk.Button(root, text="Hidden Action", command=lambda: load_save_hotkey(0))
slot_1_button = tk.Button(root, text="Hidden Action", command=lambda: load_save_hotkey(1))
slot_2_button = tk.Button(root, text="Hidden Action", command=lambda: load_save_hotkey(2))

load_config()

root.mainloop()