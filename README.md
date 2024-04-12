# dns-packet-parser

This repo presents a `Perl` script which reads a DNS Hexdump and presents the output in a standard Dig response format.

Usage:
```
$ perl packet_parse.pl 90518180000100040000000103777777096d6963726f736f667403636f6d0000010001c00c000500010000072a002303777777096d6963726f736f667407636f6d2d632d3307656467656b6579036e657400c02f0005000100000113003703777777096d6963726f736f667407636f6d2d632d3307656467656b6579036e65740b676c6f62616c726564697206616b61646e73c04dc05e000500010000011200190665313336373804647363620a616b616d616965646765c04dc0a100010001000000120004adde0ddb0000290200000000000000
```
Output:
```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36945
;; flags: qr rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;www.microsoft.com.     IN      A

;; ANSWER SECTION:
www.microsoft.com.      1834    IN      CNAME   www.microsoft.com-c-3.edgekey.net.
www.microsoft.com-c-3.edgekey.net.      275     IN      CNAME   www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.
www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net.       274     IN      CNAME   e13678.dscb.akamaiedge.net. 
e13678.dscb.akamaiedge.net.     18      IN      A       173.222.13.219
```

Currently supports:
`A, AAAA, NS CNAME, SOA`

# How to get a DNS hexdump?

## Wireshark:
0. Start capturing DNS traffic via Wireshark
1. Permform a query: `$ dig www.microsoft.com`
2. Click on the "Standard query response` line item
<img width="438" alt="image" src="https://github.com/danReleases/dns-packet-parser/assets/40340005/f292b57f-f8a2-4400-91c3-d28e7f4ae68d">

3. Click on `Domain Name System (response)` in the window below
<img width="548" alt="image" src="https://github.com/danReleases/dns-packet-parser/assets/40340005/32be80c9-c1e2-4e2f-a013-5ad20f4a2597">

5. `Right-click` > `Copy` > `...as a Hex Stream`
6. Paste to script
