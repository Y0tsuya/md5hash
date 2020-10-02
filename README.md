# md5hash
Attach MD5 checksums to NTFS ADS

I have a full backup Drivepool array using 5x SA120 enclosures. Due to the large number of drives it's not practical for me to SnapRAID it, so I'm running it without parity protection. Stablebit Scanner chokes on any setup with a large number of drives, so that's out. So what's a datahoarder to do short of resorting to ZFS or ReFS?

A MD5 checksum would be nice. If a bit gets flipped it would show up in a MD5 check which I can then easily fix with the other copy. Sure I can run a ready-made MD5 utility and save the results in a database or something, but things get messy when a file is moved or renamed. It would be a maintenance nightmare.

Then I stumbled across something called ADS (Altenate Data Streams) in NTFS. It's basically free-form metadata that will stay together with each file, and you can create as many as you like. However there are some limitations, so this feature is not advertised and is buried deep in the API, therefore not many non-MS software supports it. The metadata is lost if you overwrite the file with a non-ADS-aware software. It's also lost if you move the file to another file system (duh). But even with these limitations, the ADS functionality is perfect for attaching a MD5 checksum to a file.

Armed with this information, I wrote a C# .NET console application that can generate and attach/detach MD5 checksums to any file (that I know of). The tab-delimited output can be dumped to a unicode text file then imported Excel if you like.

Run this without arguments to get the commnad-line help.

```
md5hash -[mode] -target [file] -min [size] -max [size] -followlink
        modes:
        -read: read attached md5 stream
        -generate: generate and print md5 checksum
        -verify: generate md5 and verify against attached checksum
        -attach: generate md5 and attach it to the target
        -detach: detach md5 checksum from the target
        -min: minimum file size to consider (in bytes), defaults to 0
        -max: maximum file size to consider (in bytes), defaults to 64-bit max
        -followlink: follow soft links
