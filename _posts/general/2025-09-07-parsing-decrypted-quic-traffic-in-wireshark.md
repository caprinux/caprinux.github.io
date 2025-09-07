---
title: "Decrypting and parsing HTTP/3 traffic in Wireshark"
description: HTTP/3 
date: 2025-09-07 00:00:00 +0800
categories: [Challenge Creation,Research]
tags: [forensics]
img_path: /assets/posts/2025-09-07-parsing-decrypted-quic-traffic-in-wireshark/
---

I was writing a forensics CTF challenge for a CTF organized by [ISC2 SG Youth Wing](https://www.isc2chapter.sg/youth-wing) and I wanted to write a challenge where the participants had to decrypt some HTTPS traffic with a SSLKEYLOGFILE to be able to view and export the HTTP objects within the decrypted traffic.

However, this soon proved to be more difficult than I thought due to the recent and quick adoption of [HTTP/3](https://en.wikipedia.org/wiki/HTTP/3) in modern browsers and web servers.

This will be a short post to document some of the tips and tricks that I felt was useful to analyze HTTP/3 traffic.

## HTTP/3 (QUIC + TLS 1.3)

> HTTP/3 was first proposed in 2018, officially published as a standard in 2022, and supported by >95% of major web browsers and 35.6% of the top 10 million websites as of this post.
{:.prompt-tip}

Unlike the traditional HTTP/2 specificiation where HTTPS traffic runs with TLS on top of TCP, HTTP/3 uses [QUIC](https://en.wikipedia.org/wiki/QUIC) _(a UDP protocol)_ that is directly integrated with TLS 1.3 to allow web traffic to be more performant and resilient.

For the rest of the post, I will be referencing the sample pcap [here](/assets/posts/2025-09-07-parsing-decrypted-quic-traffic-in-wireshark/traffic.pcapng) and the accompanying sslkeylog file [here](/assets/posts/2025-09-07-parsing-decrypted-quic-traffic-in-wireshark/sslkey.log).

## Analyzing HTTP/3 traffic in Wireshark

**traffic.pcapng** contains some firefox browser traffic. If you open it on its own, you would notice many QUIC traffic without much information. That is because the contents of the packets are still encrypted with TLS 1.3.

### Decrypting HTTP/3 traffic

Since HTTP/3 traffic is still encrypted the same way as older specifications **(over TLS 1.3)**, we can decrypt it the same way that we would decrypt it typically.

Pass the sslkeylog file into Wireshark via `Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename`.

![](tlskeylogfile.png)
_passing sslkeylog file into wireshark_

Upon successful decryption, you should be able to identify some HTTP3 traffic.

![](decrypted_http3_packets.png)

However, it is still not simple to read into the HTTP/3 traffic and searching for strings via Ctrl+F in Wireshark would also yield no result.

Both the traditional ways of exporting HTTP files via `File > Export Objects... > HTTP` and viewing streams also do not work for viewing HTTP3 traffic.

### Parsing the decrypted HTTP/3 traffic

If we peek into a single HTTP3 packet, we see that Wireshark is able to dissect and show us the HTTP headers.

![](decrypted_http3_packet.png)

This is great, but it is probably inefficient to look into every packet and find the packets with HTTP headers.

![](wireshark_http3_header_fields.png)

If we right click on the `http3.headers.header.value` field and apply it as a column, we can easily view all the HTTP3 header values alongside our packets!

![](http3_headers.png)

From the picture above, we can easily identify the different HTTP request and response headers. However, it is still rather troublesome to have to filter through the noise.

To go one step further, we can export the current listing into a CSV (`File > Export Packet Dissections > As CSV`) to further process the data to filter away any noise and process the HTTP3 data.

### Extracting HTTP3 Downloads

What about file downloads over HTTP3? How do we extract them if they are not available under the `Export Objects` feature?

If you are able to find the request that fetches a file, we can actually dump the file by identifying and dumping the reassembled QUIC data.

![](identifying_the_response.png)

From the above picture, we can see the following

1. Identify the GET request for the downloaded file
2. Click on the response packet
3. Find the packet with the DOT _(indicating that it's the last fragment)_

Next, we click on the packet with the DOT

![](getting_the_response_file.png)

We can click on the `Reassembled QUIC` at the bottom right of the PCAP file to be able to see the reassembled file.

To get the bytes out, we can right click on the `Data[...]` and then `Copy` in format of your preference.

Typically, I will copy it as a **hex stream** and use python `bytes.fromhex` to write it to a file.

## Conclusion

Although it seemed rather simple, these were some of the instructions that I hoped I knew before getting started on analyzing the HTTP3 packets and took me some time to figure it out on my own.

If you find a more efficient way/feature or have any cool tips/tricks of your own that you would like to share, feel free to reach out to me via my discord `@caprinux`{:.filepath}.

Thanks for reading!
