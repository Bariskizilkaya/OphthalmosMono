import gdb
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

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
    """Iterate over the task list and return the first task with comm == comm_name."""
    try:
        init_task = gdb.parse_and_eval("init_task")
        task = init_task.address
        head = init_task['tasks'].address
        current = head['next']
        while current != head:
            # Get the containing struct task_struct from the list_head pointer
            task_addr = int(current) - int(init_task.type['tasks'].bitpos // 8)
            task_obj = gdb.Value(task_addr).cast(init_task.type.pointer())
            comm = str(task_obj['comm'])
            if comm_name in comm:
                return task_obj
            current = current['next']
        return None
    except Exception as e:
        return None

def get_init_task_data():
    global selected_comm
    try:
        if selected_comm:
            task = get_task_by_comm(selected_comm)
            if task is None:
                return {"error": f"No task with comm containing '{selected_comm}' found."}
        else:
            task = gdb.parse_and_eval("init_task")
        data = {
            "pid": int(task['pid']),
            "comm": str(task['comm']),
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

class InitTaskHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            try:
                #Change the path of the index.html
                with open("/home/asd/Documents/projects/OphthalmosMono/gdbscripts/index.html", "rb") as f:
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
