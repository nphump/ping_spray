Synopsis:
Multiplexes ICMP requests (pings) to a large number of IPv4 addresses in an input file, quickly outputting which hosts are available.
On UNIX, will typically need to be run with high privileges.

Compilation:
UNIX - See make_ping_spray_unix.sh
WINDOWS - cl.exe /Ox /MT /EHsc ping_spray_windows.cpp Ws2_32.lib /Fe:ping_spray.exe