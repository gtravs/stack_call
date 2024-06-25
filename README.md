### 在堆栈欺骗基础上使用回调函数自定义堆栈    
`api.ntdll.TpSimpleTryPost = (tTPSIMPLETRYPOST) xGetProcAddress_hash(TPSIMPLETRYPOST,&ntdll);`
`(api.ntdll.TpSimpleTryPost)((PTP_SIMPLE_CALLBACK)(unsigned char*)WorkCallback, lib_name, 0);`

### shellcode 生成
``` c
x86_64-w64-mingw32-objcopy -O binary -j .text stackcall.exe  shellcode.bin
```

![image](https://github.com/gtravs/stack_call/assets/53836933/cff37da2-3f87-4fd3-9474-7da5e9ab6b13)


### 参考项目
https://github.com/boku7/BokuLoader.git

https://github.com/hlldz/misc/tree/main/proxy_calls

