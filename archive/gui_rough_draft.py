import tkinter as tk
from tkinter import messagebox
import json
from random import randint

def handle_mode_selection(choice):
    #Enable or auto-fill device entries based on dropdown selection
    if choice == "Enter manually":
        for entry in all_entries:
            entry.config(state="normal")
            entry.delete(0, tk.END)
    elif choice == "Generate randomly":
        values = {
            switch_entry: randint(1, 3),
            hub_entry: randint(0, 2),
            wlan_entry: 0,
            pc_entry: randint(1, 10),
            router_entry: randint(1, 3),
            mdr_entry: 0
        }
        for entry, value in values.items():
            entry.config(state="normal")
            entry.delete(0, tk.END)
            entry.insert(0, value)
            entry.config(state="normal")

def show_dynamic_content(option):
    #Show relevant content (LLM prompt box) based on selected link option
    for widget in response_frame.winfo_children():
        widget.destroy()

    if option == "autogenerate":
        tk.Label(response_frame, text="Autogeneration selected. Links will be generated automatically.", fg="blue").pack()
    
    elif option == "manual":
        tk.Label(response_frame, text="Manual linking selected. You will define links.", fg="green").pack()
    elif option == "llm":
        tk.Label(response_frame, text="LLM selected. Enter your prompt below:", fg="purple").pack(anchor="w")
        global llm_prompt_box
        llm_prompt_box = tk.Text(response_frame, height=5, width=60)
        llm_prompt_box.pack(pady=5)

def generate_random_links(device_id_map):
    links = []
    seen_links = set()

    # Group devices by type
    routers = [dev_id for dev_id, dev_type in device_id_map.items() if dev_type.lower() == "router"]
    switch_and_hubs = [dev_id for dev_id, dev_type in device_id_map.items() if dev_type.lower() in ("switch", "hub")]
    pcs = [dev_id for dev_id, dev_type in device_id_map.items() if dev_type.lower() == "pc"]

    # Link routers to each other (full mesh)
    for i in range(len(routers)):
        for j in range(i + 1, len(routers)):
            r1, r2 = routers[i], routers[j]
            link = tuple(sorted((r1, r2)))
            if link not in seen_links:
                links.append([r1, r2])
                seen_links.add(link)

    # Attach each switch/hub to a router
    router_index = 0
    for device_id in switch_and_hubs:
        if routers:
            router_id = routers[router_index % len(routers)]
            link = tuple(sorted((device_id, router_id)))
            if link not in seen_links:
                links.append([device_id, router_id])
                seen_links.add(link)
            router_index += 1

    # Attach PCs to routers or switch/hubs
    parent_devices = switch_and_hubs + routers
    parent_index = 0
    for pc in pcs:
        for _ in range(len(parent_devices)):
            parent = parent_devices[parent_index % len(parent_devices)]
            link = tuple(sorted((pc, parent)))
            if link not in seen_links:
                links.append([pc, parent])
                seen_links.add(link)
                parent_index += 1
                break
            parent_index += 1

    return links


def enable_submit():
    submit_btn.config(state="normal")

def submit():
    try:
        # Ensure all fields are active to read values
        for entry in all_entries:
            entry.config(state="normal")

        devices = {
            "SWITCH": int(switch_entry.get()),
            "HUB": int(hub_entry.get()),
            "WIRELESS_LAN": int(wlan_entry.get()),
            "PC": int(pc_entry.get()),
            "router": int(router_entry.get()),
            "mdr": int(mdr_entry.get())
        }
        
        if devices["SWITCH"] > devices["router"]:
            messagebox.showerror("Invalid Topology", "Number of switches cannot exceed the number of routers.")
            return


        link_option = link_choice.get()

        if not link_option:
            messagebox.showerror("Selection missing", "Please select a link generation option.")
            return

        data = {
            "device_mode": entry_mode_var.get().lower().replace(" ", "_"),
            "devices": devices,
            "link_option": link_option
        }

        if link_option == "llm":
            # prompt_text = llm_prompt_box.get("1.0", tk.END).strip() if llm_prompt_box else ""
            # if not prompt_text:
            #     messagebox.showerror("Prompt missing", "Please enter a prompt for LLM.")
            #     return
            # data["llm_prompt"] = prompt_text
            print("choose llm")
        


        # with open("topology_config.json", "w") as f:
        #     json.dump(data, f, indent=4)

        # Create ID-to-device mapping dictionary
        device_id_map = {}
        current_id = 1
        for device_type, count in devices.items():
            for _ in range(count):
                device_id_map[current_id] = device_type
                current_id += 1

        # Store in variable or pass to next part of the program
        print("Device ID Map:", json.dumps(device_id_map, indent=4))

        if link_option == "autogenerate":
            links = generate_random_links(device_id_map)
            print("Generated Links:")
            print(json.dumps(links, indent=4))

        # messagebox.showinfo("Saved", "Configuration saved to topology_config.json")
        show_dynamic_content(link_option)

    except ValueError:
        messagebox.showerror("Invalid input", "All values must be integers.")

    finally:
        # Redisable entries if they were generated randomly
        if entry_mode_var.get() == "Generate randomly":
            for entry in all_entries:
                entry.config(state="disabled")

# Main window
root = tk.Tk()
root.title("CORE Topology Generator")

frame = tk.Frame(root, padx=20, pady=20)
frame.grid(row=0, column=0)

# === Entry mode dropdown ===
entry_mode_var = tk.StringVar(value="Enter manually")

tk.Label(frame, text="Device Entry Mode:").grid(row=0, column=0, sticky="w", padx=5, pady=(0, 10))
entry_mode_dropdown = tk.OptionMenu(frame, entry_mode_var, "Enter manually", "Generate randomly", command=handle_mode_selection)
entry_mode_dropdown.grid(row=0, column=1, sticky="w", pady=(0, 10))

# === Device input fields ===
def make_input(label_text, row):
    label = tk.Label(frame, text=label_text)
    label.grid(row=row, column=0, sticky="w", padx=5, pady=5)
    entry = tk.Entry(frame, justify="left")
    entry.grid(row=row, column=1, sticky="w", padx=5, pady=5)
    return entry

switch_entry = make_input("SWITCH:", 2)
hub_entry = make_input("HUB:", 3)
wlan_entry = make_input("WIRELESS_LAN:", 4)
pc_entry = make_input("PC:", 5)
router_entry = make_input("ROUTER:", 6)
mdr_entry = make_input("mdr:", 7)

all_entries = [switch_entry, hub_entry, wlan_entry, pc_entry, router_entry, mdr_entry]

# === Link generation options ===
link_choice = tk.StringVar()

tk.Label(frame, text="Choose Link Generation Method:").grid(row=8, column=0, columnspan=2, pady=(20, 5), sticky="w")

tk.Radiobutton(frame, text="Autogenerate", variable=link_choice, value="autogenerate", command=enable_submit, anchor="w", width=30)\
    .grid(row=9, column=0, columnspan=2, sticky="w", padx=20)
tk.Radiobutton(frame, text="Manually Link", variable=link_choice, value="manual", command=enable_submit, anchor="w", width=30)\
    .grid(row=10, column=0, columnspan=2, sticky="w", padx=20)
tk.Radiobutton(frame, text="Use LLM", variable=link_choice, value="llm", command=enable_submit, anchor="w", width=30)\
    .grid(row=11, column=0, columnspan=2, sticky="w", padx=20)

# === Submit button ===
submit_btn = tk.Button(frame, text="Submit", command=submit, state="disabled")
submit_btn.grid(row=12, column=0, columnspan=2, pady=20)

# === Dynamic response area below form ===
response_frame = tk.Frame(root, padx=20, pady=10)
response_frame.grid(row=1, column=0)

llm_prompt_box = None

root.mainloop()
