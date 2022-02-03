# harderdns

a dns server that proxies queries concurrently to multiple upstreams, retries and timeouts faster

```
$ harderdns 8.8.8.8:53 1.1.1.1:53
2022/02/03 10:24:11 Starting at :53 using udp
49fe59a6-ace6-4c73-9358-8552ca508c03	QUERY	A	www.microsoft.com.
49fe59a6-ace6-4c73-9358-8552ca508c03	GOT	A	www.microsoft.com. 1.1.1.1:53	61.682057ms
49fe59a6-ace6-4c73-9358-8552ca508c03	GOT	A	www.microsoft.com. 8.8.8.8:53	61.582191ms
49fe59a6-ace6-4c73-9358-8552ca508c03	ANSWER	A	www.microsoft.com. NOERROR	4,0,0
```
