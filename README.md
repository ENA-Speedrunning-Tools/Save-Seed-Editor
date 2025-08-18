# Save Seed Editor

This is a tool for **ENA: Dream BBQ** that allows extacting and editing the seed value inside of save files. There is also an option to reset a save file with it's current seed.

Simply select the folder where your game's save files are stored to get started. On Windows, this folder should be located at `C:\Users\{user}\AppData\LocalLow\JoelG\ENA-4-DreamBBQ\saves\steam\{number}`

Hotkeys can be bound to trigger each of the tool's button actions by editing the `config.ini` file that is bundled in the `.zip` folder. If making changes to the config file while the tool is open, click the *Refresh* button to apply the changes.

<details>
<summary>How to bind Hotkeys</summary>

###

The tool makes use of the Python `keyboard` library to bind hotkeys

Valid hotkey names include :

* a - z
* 0 - 9 (top row number keys)
* f1 - f12
* left_shift, right_shift, left_ctrl, right_ctrl, left_alt, right_alt, windows, cmd
* up, down, left, right, home, end, page_up, page_down
* space, enter, backspace, tab, escape, caps_lock, print_screen, insert, delete
* num_1 - num_9, num_plus, num_minus, num_multiply, num_divide, num_lock (numpad keys)

'+' can be placed between key names to create a *key sequence*, which will trigger the associated action when all keys in the sequence are pressed down in any order

Example config :

```
[Hotkeys]
refresh = f1
change_seed = f2
wipe_data = shift+f2 // Key sequence
select_folder = ctrl+shift+f3 // Longer key sequence
```

</details>

###

***This is a very old version of the tool that may or may not be updated in the future***