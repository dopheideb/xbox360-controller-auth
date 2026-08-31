# Introduction

The LEGO Dimensions Toypad is said to use different keys than the 0x1D 
and 0x1E keys. Using a man in the middle (GIMX on Arduino Leonardo), we 
sniffed the traffic, and recorded it.



# UsbdSecXSM3GetIdentificationProtocolData

Host's IN control transfer:
```
c1 81 17 5b 03 01 1d 00
```

Toypad's response:
```
49 4b 00 00 17 74 ff 25   53 0e 11 85 25 38 03 20
00 00 80 82 c6 24 00 50   03 00 01 01 ea
```



# UsbdSecXSM3SetChallengeProtocolData

Host's OUT control transfer:
```
41 82 03 00 03 01 22 00

09 40 00 00 1c b6 9e e4   d8 f7 25 22 2c d8 d6 d2
52 25 5c 79 bb 26 4c fd   e5 5b be 5b b3 c8 5a 0e
d7 c9
```

Toypad's response: (zero data)



# UsbdSecXSM3GetStatus

Host's IN control transfer:
```
c1 86 00 00 03 01 02 00
```

Toypad's response the first time:
```
01 00
```

Toypad's response the second time:
```
02 00
```



# ???

Host's IN control transfer:
```
c1 83 28 5c 03 01 2e 00
```

Toypad's response:
```
49 4c 00 00 28 b7 7e aa   c6 5b 1e 9f cb 18 25 73
c1 ef 87 5f 7c 4b 97 6f   65 27 8b d0 c7 6f 94 f1
b9 7e 6e 65 92 72 59 15   31 b9 ca 35 5d 5d
```


# Pass?

Host's OUT control transfer:
```
41 84 03 00 03 01 00 00
```

Toypad's response: (zero data)



# ?Challenge 2?

Host's OUT control transfer:
```
41 87 03 00 03 01 16 00

09 41 00 00 10 06 33 fb   2e 1d 5b de 3a d9 7c 86
27 1e 0f 3a c7 aa
```

Toypad's response: (zero data)



# UsbdSecXSM3GetStatus

Host's IN control transfer:
```
c1 86 00 00 03 01 02 00
```

Toypad's response the first time:
```
01 00
```

Toypad's response the second time:
```
02 00
```



# ???

Host's IN control transfer:
```
c1 83 10 5c 03 01 16 00

```

Toypad's response:
```
49 4c 00 00 10 18 19 25   45 ad f5 48 f3 20 f7 87
e0 3f 9f 9d da d5
```



# ???

Host's OUT control transfer:
```
41 87 03 00 03 01 16 00

```

Toypad's response: (zero data)



# UsbdSecXSM3GetStatus

Host's IN control transfer:
```
c1 86 00 00 03 01 02 00
```

Toypad's response the first time:
```
01 00
```

Toypad's response the second time:
```
02 00
```



# ???

Host's IN control transfer:
```
c1 83 10 5c 03 01 16 00
```

Toypad's response:
```
49 4c 00 00 10 47 47 98   fa 3f e2 2d 0f 96 f0 db
2b 6c 4d 78 d5 87
```
