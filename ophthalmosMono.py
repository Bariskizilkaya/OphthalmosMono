import gdb
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from urllib.parse import parse_qs, urlparse
import re

selected_comm = None

def get_kmem_cache_cpu(kmem_cache, cpu_id=0):
    per_cpu_offset = gdb.lookup_symbol("__per_cpu_offset")[0].value()
    gdb.write(f"per_cpu_offset: {per_cpu_offset}\n")
    offset = int(per_cpu_offset[cpu_id])
    gdb.write(f"Offset for CPU {cpu_id}: {offset}\n")
    cpu_slab_ptr = kmem_cache["cpu_slab"]
    gdb.write(f"cpu_slab_ptr: {cpu_slab_ptr}\n")
    kmem_cache_cpu_addr = cpu_slab_ptr + offset
    gdb.write(f"kmem_cache_cpu_addr: {kmem_cache_cpu_addr}\n")
    kmem_cache_cpu = kmem_cache_cpu_addr.dereference()
    gdb.write(f"kmem_cache_cpu {kmem_cache_cpu}")
    return kmem_cache_cpu

def get_task_by_comm(comm_name):
    """Return the first task_struct dict with comm containing comm_name."""
    try:
        init_task = gdb.parse_and_eval("init_task")
        head = init_task['tasks'].address
        current = head['next']
        while current != head:
            # Get the containing struct task_struct from the list_head pointer
            task_addr = int(current) - int(init_task.type['tasks'].bitpos // 8)
            task_obj = gdb.Value(task_addr).cast(init_task.type.pointer())
            comm = str(task_obj['comm'])
            if comm_name in comm:
                # Return a dict with all relevant fields
                return {
                    "pid": int(task_obj['pid']),
                    "comm": comm,
                    "__state": int(task_obj['__state']),
                    "saved_state": int(task_obj['saved_state']),
                    "flags": int(task_obj['flags']),
                    "prio": int(task_obj['prio']),
                    "on_cpu": int(task_obj['on_cpu']),
                    "exit_state": int(task_obj['exit_state']),
                }
            current = current['next']
        return None
    except Exception as e:
        return {"error": str(e)}

def get_init_task_data():
    global selected_comm
    try:
        if selected_comm:
            task = get_task_by_comm(selected_comm)
            if task is None:
                return {"error": f"No task with comm containing '{selected_comm}' found."}
        else:
            task = gdb.parse_and_eval("init_task")
        comm_str = str(task['comm']).strip('"').replace('\\000', '').replace('\x00', '').strip()
        data = {
            "pid": int(task['pid']),
            "comm": comm_str,
            "__state": int(task['__state']),
            "saved_state": int(task['saved_state']),
            "flags": int(task['flags']),
            "prio": int(task['prio']),
            "on_cpu": int(task['on_cpu']),
            "exit_state": int(task['exit_state']),
        }
        return data
    except Exception as e:
        return {"error": str(e)}
    
def get_all_symbols_json():
    """Return all global symbols and their addresses as a JSON-serializable dict."""
    symbols = []
    try:
        output = gdb.execute("info variables", to_string=True)
        for line in output.splitlines():
            if "0x" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.startswith("0x"):
                        symbol = parts[i-1]
                        address = part
                        symbols.append({"symbol": symbol, "address": address})
                        print(f"Symbol: {symbol}, Address: {address}\n")
        return symbols
    except Exception as e:
        return [{"error": str(e)}]

def get_registers_json():
    """Return all general-purpose registers and their values as a JSON-serializable dict."""
    registers = {}
    try:
        output = gdb.execute("info registers", to_string=True)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                reg = parts[0]
                val = parts[1]
                registers[reg] = val
        return registers
    except Exception as e:
        return {"error": str(e)}

def get_all_tasks():
    """Return a list of all tasks (processes/threads) from the kernel's task_struct list."""
    try:
        init_task = gdb.parse_and_eval("init_task")
        head = init_task['tasks'].address
        current = head['next']
        tasks = []

        while current != head:
            task_addr = int(current) - int(init_task.type['tasks'].bitpos // 8)
            task_obj = gdb.Value(task_addr).cast(init_task.type.pointer())
            comm = str(task_obj['comm']).strip('"').replace('\\000', '').replace('\x00', '').strip()
            tasks.append({
                "pid": int(task_obj['pid']),
                "comm": comm,
                "__state": int(task_obj['__state']),
                "saved_state": int(task_obj['saved_state']),
                "flags": int(task_obj['flags']),
                "prio": int(task_obj['prio']),
                "on_cpu": int(task_obj['on_cpu']),
                "exit_state": int(task_obj['exit_state']),
            })
            current = current['next']

        # Also include init_task itself
        comm_init = str(init_task['comm']).strip('"').replace('\\000', '').replace('\x00', '').strip()
        tasks.insert(0, {
            "pid": int(init_task['pid']),
            "comm": comm_init,
            "__state": int(init_task['__state']),
            "saved_state": int(init_task['saved_state']),
            "flags": int(init_task['flags']),
            "prio": int(init_task['prio']),
            "on_cpu": int(init_task['on_cpu']),
            "exit_state": int(init_task['exit_state']),
        })

        return tasks
    except Exception as e:
        return [{"error": str(e)}]

def get_slub_memory_usage():
    """Return SLUB memory usage for all caches as a list of dicts, including total slabs and objects (advanced)."""
    caches = []
    MAX_NUMNODES = 1024  # Typical value, may be less in your kernel
    try:
        kmalloc_caches = gdb.parse_and_eval("kmalloc_caches")
        for i in range(0, 256):
            entry = kmalloc_caches.dereference()[i]
            try:
                if int(entry) == 0:
                    continue  # Skip null pointers
            except Exception:
                continue
            try:
                cache = entry.dereference()
                name = str(cache['name']).strip('"').replace('\\000', '').replace('\x00', '').strip()
                addr = str(entry)
                # Use available fields
                try:
                    object_size = int(cache['object_size'])
                except Exception:
                    object_size = None
                try:
                    inuse = int(cache['inuse'])
                except Exception:
                    inuse = None
                try:
                    size = int(cache['size'])
                except Exception:
                    size = None
                # Advanced: try to sum total slabs and objects from node array
                total_slabs = 0
                total_objects = 0
                try:
                    node_ptr = cache['node']
                    for n in range(MAX_NUMNODES):
                        try:
                            node = node_ptr[n]
                            # Try common field names
                            try:
                                slabs = int(node['nr_slabs'])
                            except Exception:
                                slabs = 0
                            try:
                                objs = int(node['total_objects'])
                            except Exception:
                                objs = 0
                            total_slabs += slabs
                            total_objects += objs
                        except Exception:
                            continue
                except Exception:
                    total_slabs = None
                    total_objects = None
                caches.append({
                    "name": name,
                    "address": addr,
                    "object_size": object_size,
                    "inuse": inuse,
                    "size": size,
                    "total_slabs": total_slabs if total_slabs != 0 else None,
                    "total_objects": total_objects if total_objects != 0 else None
                })
            except Exception:
                continue
        return {"caches": caches}
    except Exception as e:
        return {"error": str(e), "caches": caches}

class InitTaskHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            try:
                #Change the path of the index.html
                with open("/home/asd/Documents/projects/opt/OphthalmosMono/index.html", "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Error: {e}".encode())
        elif self.path == "/init_task":
            data = get_init_task_data()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        elif self.path == "/symbols":
            print("GET /symbols called")  # Add this line
            symbols = get_all_symbols_json()
            print(f"Symbols: {symbols}")  # Add this line
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(symbols).encode())
        elif self.path == "/registers":
            regs = get_registers_json()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(regs).encode())
        elif self.path.startswith("/task_by_comm"):
            # Parse comm name from query string
            query = urlparse(self.path).query
            params = parse_qs(query)
            comm_name = params.get("comm", [""])[0]
            data = get_task_by_comm(comm_name)
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        elif self.path == "/all_tasks":
            tasks = get_all_tasks()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(tasks).encode())
        elif self.path == "/slub_memory":
            usage = get_slub_memory_usage()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(usage).encode())
        else:
            self.send_response(404)
            self.end_headers()

def start_server():
    server = HTTPServer(('localhost', 8000), InitTaskHandler)
    print("Serving init_task status at http://localhost:8000/")
    server.serve_forever()

class InitTaskServer(gdb.Command):
    """Start HTTP server to serve live init_task status."""

    def __init__(self):
        super(InitTaskServer, self).__init__("serve_init_task", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global selected_comm
        selected_comm = arg.strip() if arg else None
        t = threading.Thread(target=start_server, daemon=True)
        t.start()
        print(f"HTTP server started in background. Filtering for comm: {selected_comm}")
        #kmalloc_caches = gdb.lookup_global_symbol("kmalloc_caches").value()
        #gdb.write(f"kmem_cache 0x{int(kmalloc_caches.address):x}\n")
        #get_kmem_cache_cpu(kmalloc_caches[0][1])

InitTaskServer()

