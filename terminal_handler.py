import os
import pty
import select
import termios
import struct
import fcntl
import asyncio
from flask_socketio import emit
from models import TerminalSession, RemoteSession
from database import db

class TerminalHandler:
    def __init__(self, session_id):
        self.session_id = session_id
        self.fd = None
        self.pid = None
        self.terminal_session = None
    
    async def create_terminal(self, cols=80, rows=24):
        pid, fd = pty.fork()
        
        if pid == 0:  # Child process
            os.execvp('/bin/bash', ['/bin/bash'])
        else:  # Parent process
            self.pid = pid
            self.fd = fd
            
            # Create terminal session record
            remote_session = RemoteSession.query.get(self.session_id)
            self.terminal_session = TerminalSession(
                session_id=self.session_id,
                shell_type='bash',
                cols=cols,
                rows=rows,
                log_file=f"/tmp/terminal_{self.session_id}.log"
            )
            db.session.add(self.terminal_session)
            db.session.commit()
            
            # Set terminal size
            self.resize_terminal(cols, rows)
            
            return True
    
    def resize_terminal(self, cols, rows):
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ,
                       struct.pack("HHHH", rows, cols, 0, 0))
        except Exception as e:
            print(f"Error resizing terminal: {e}")
    
    async def read_output(self):
        max_read_bytes = 1024 * 20
        while True:
            try:
                r, w, e = select.select([self.fd], [], [], 0.1)
                if self.fd in r:
                    output = os.read(self.fd, max_read_bytes).decode()
                    if output:
                        # Log output
                        with open(self.terminal_session.log_file, 'a') as f:
                            f.write(output)
                        
                        # Emit output to client
                        emit('terminal_output', {
                            'session_id': self.session_id,
                            'output': output
                        })
            except Exception as e:
                print(f"Error reading terminal output: {e}")
                break
    
    async def write_input(self, data):
        try:
            os.write(self.fd, data.encode())
        except Exception as e:
            print(f"Error writing to terminal: {e}")
    
    def cleanup(self):
        try:
            if self.pid:
                os.kill(self.pid, 9)
            if self.fd:
                os.close(self.fd)
        except Exception as e:
            print(f"Error cleaning up terminal: {e}")

# Terminal WebSocket handlers
terminal_handlers = {}

def handle_terminal_connect(session_id, cols=80, rows=24):
    handler = TerminalHandler(session_id)
    terminal_handlers[session_id] = handler
    asyncio.create_task(handler.create_terminal(cols, rows))

def handle_terminal_input(session_id, data):
    handler = terminal_handlers.get(session_id)
    if handler:
        asyncio.create_task(handler.write_input(data))

def handle_terminal_resize(session_id, cols, rows):
    handler = terminal_handlers.get(session_id)
    if handler:
        handler.resize_terminal(cols, rows)

def handle_terminal_disconnect(session_id):
    handler = terminal_handlers.pop(session_id, None)
    if handler:
        handler.cleanup()
