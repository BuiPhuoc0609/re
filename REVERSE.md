---
title: REVERSE

---

Bài dễ thì mình làm chậm mà bài khó thì không làm được :((  
Do mình làm bài chưa được tốt nên sẽ cố gắng viết WU chi tiết và đầy đủ ý nhất  
# REVERSE  
## HIDDEN  
![image](https://hackmd.io/_uploads/ByTm-9cD1e.png)  
mở ida dễ dàng thấy flag  
![image](https://hackmd.io/_uploads/HyLNG9cv1g.png)  
submit thử thì báo incorrect, rõ ràng là fakeflag  
vào functions thấy hàm printFlag khả nghi  
![image](https://hackmd.io/_uploads/H1G0K9qDkg.png)  
Xem mã giả ta dễ dàng thấy đây chỉ là mã hóa xor từng byte của v2 với \x88  
![image](https://hackmd.io/_uploads/H1Qtc5qwJg.png)  
bài này warmup nên có thể giải nhanh bằng cách debug và nhảy RIP đến hàm printFlag  
![image](https://hackmd.io/_uploads/ByLjpcqDkx.png)  
Flag: ~~KCSC{you_can't_see_me:v}~~  
![image](https://hackmd.io/_uploads/HynMA9qwye.png)  

## easyre  

![image](https://hackmd.io/_uploads/r1GGkj9vkl.png)  
chạy thử:  
![image](https://hackmd.io/_uploads/SkEEliqvyx.png)  
pseudo code:  
```C=
int __cdecl sub_7FF78B081280(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  size_t v4; // rax
  __int64 v5; // rdx
  __int64 v6; // rcx
  __int64 v7; // r8
  __int64 v8; // r9
  __int64 v9; // rax
  unsigned int v10; // edx
  unsigned int v11; // r8d
  unsigned __int64 v12; // rax
  __m128 v13; // xmm0
  __m128 v14; // xmm1
  __int64 v15; // rcx
  __int64 v16; // rax
  char *v17; // rcx
  char Buffer[16]; // [rsp+20h] [rbp-68h] BYREF
  __int128 v20; // [rsp+30h] [rbp-58h] BYREF
  int v21; // [rsp+40h] [rbp-48h]
  __int128 v22[2]; // [rsp+48h] [rbp-40h] BYREF
  __int64 v23; // [rsp+68h] [rbp-20h]
  int v24; // [rsp+70h] [rbp-18h]
  char v25; // [rsp+74h] [rbp-14h]

  LOBYTE(v21) = 0;
  v23 = 0i64;
  *(_OWORD *)Buffer = 0i64;
  v24 = 0;
  v20 = 0i64;
  v25 = 0;
  memset(v22, 0, sizeof(v22));
  sub_7FF78B081010("Enter flag: ");
  v3 = _acrt_iob_func(0);
  fgets(Buffer, 33, v3);
  v4 = strcspn(Buffer, "\n");
  if ( v4 >= 0x21 )
  {
    sub_7FF78B081558(
      v6,
      v5,
      v7,
      v8,
      *(_QWORD *)Buffer,
      *(_QWORD *)&Buffer[8],
      v20,
      *((_QWORD *)&v20 + 1),
      v21,
      *(_QWORD *)&v22[0],
      *((_QWORD *)&v22[0] + 1));
    JUMPOUT(0x7FF78B08141Ei64);
  }
  Buffer[v4] = 0;
  v9 = -1i64;
  do
    ++v9;
  while ( Buffer[v9] );
  if ( v9 == 32 )
  {
    sub_7FF78B081070(Buffer, v22);
    v10 = 0;
    v11 = 0;
    v12 = 0i64;
    do
    {
      v13 = (__m128)_mm_loadu_si128((const __m128i *)&byte_7FF78B085078[v12]);
      v11 += 32;
      v14 = (__m128)_mm_loadu_si128((const __m128i *)&v22[v12 / 0x10]);
      v12 += 32i64;
      *(__m128 *)&dword_7FF78B085058[v12 / 4] = _mm_xor_ps(v14, v13);
      *(__m128 *)&qword_7FF78B085068[v12 / 8] = _mm_xor_ps(
                                                  (__m128)_mm_loadu_si128((const __m128i *)((char *)&v20 + v12 + 8)),
                                                  (__m128)_mm_loadu_si128((const __m128i *)&qword_7FF78B085068[v12 / 8]));
    }
    while ( v11 < 0x20 );
    v15 = (int)v11;
    if ( (unsigned __int64)(int)v11 < 0x2C )
    {
      do
      {
        ++v11;
        byte_7FF78B085078[v15] ^= *((_BYTE *)v22 + v15);
        ++v15;
      }
      while ( v11 < 0x2C );
    }
    v16 = 0i64;
    while ( byte_7FF78B0832F0[v16] == byte_7FF78B085078[v16] )
    {
      ++v10;
      ++v16;
      if ( v10 >= 0x2C )
      {
        v17 = "Correct!\n";
        goto LABEL_13;
      }
    }
  }
  v17 = "Incorrect!\n";
LABEL_13:
  sub_7FF78B081010(v17);
  return 0;
}
```
xem qua ta có thể thấy chương trình gọi một số hàm mã hóa và cuối cùng là check để kiểm tra flag có đúng không  
![image](https://hackmd.io/_uploads/ryTM-jqP1e.png)  
tuy code khá dài tuy nhiên ta có thể chú ý một số hàm mã hóa chính như sau  
lần 1:  
![image](https://hackmd.io/_uploads/B1qEwo9vyx.png)
chương trình kiểm tra xem đầu vào mà ta nhập có phải là 32 ký tự hay không  
nếu đúng thì sẽ gọi hàm ```sub_7FF7EEA81070``` để mã hóa  
nội dung hàm khá dài và khó nhìn tuy nhiên ta có thể check output để xem hàm làm gì với input  
output:  
![image](https://hackmd.io/_uploads/H1Tgtscw1x.png)  
![image](https://hackmd.io/_uploads/SJ38KocPJe.png)  
ta có thể dễ dàng nhận ra đây là mã hóa base64 của input ```aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa``` mà ta đã nhập vào trước đó  
lần 2:  
![image](https://hackmd.io/_uploads/rJCEcjqwJe.png)  
xor từng bytes của ```v18``` (output của base64 trước đó) với từng bytes của ```byte_7FF6E4DF5078``` và lưu trữ kết quả luôn vào ```byte_7FF6E4DF5078```  
cuối cùng là check: ```byte_7FF6E4DF5078``` với ```byte_7FF6E4DF32F0```  
![image](https://hackmd.io/_uploads/BJbWoi5DJx.png)  
nếu tất cả các bytes ```byte_7FF6E4DF5078``` và ```byte_7FF6E4DF32F0``` đều giống nhau thì báo ```Correct!``` nếu không thì báo ```Incorrect!```
Tổng kết:  
\- nhận vào chuỗi 32 ký tự  
\- mã hóa base64  
\- xor với ```byte_7FF6E4DF5078```   
\- kiểm tra  
Ta dễ dàng viết script decrypt:  
```python=
import base64
byte_7FF6E4DF32F0=[0xC1, 0x91, 0x69, 0xB4, 0x66, 0xF9, 0x04, 0x12, 0xB2, 0xD3, 0x7D, 0x6B, 0x0F, 0xB9, 0x7F, 0xF5, 0xD2, 0x1C, 0xBF, 0x32, 0x0B, 0x32, 0x34, 0x9C, 0x98, 0xA4, 0x14, 0x37, 0x86, 0xC9, 0xAF, 0xE2, 0x9C, 0x46, 0x2B, 0xEC, 0x9F, 0x63, 0x38, 0x23, 0x54, 0x78, 0xCD, 0xF2]
byte_7FF6E4DF5078=[0x92, 0xA1, 0x27, 0xE0, 0x37, 0xCA, 0x70, 0x7E, 0xE6, 0xBE, 0x33, 0x1D, 0x5D, 0xFE, 0x29, 0x93, 0xB6, 0x66, 0xF9, 0x02, 0x6A, 0x74, 0x0D, 0xDF, 0xD6, 0xEC, 0x5A, 0x71, 0xC8, 0xA3, 0xFD, 0x84, 0xC5, 0x13, 0x1E, 0x87, 0xC7, 0x52, 0x50, 0x55, 0x01, 0x16, 0xFD, 0xCF]
a=''
for i in range(len(byte_7FF6E4DF5078)):
    a+=chr(byte_7FF6E4DF5078[i]^byte_7FF6E4DF32F0[i])
p=base64.b64decode(a.encode())
print(p.decode())
#KCSC{eNcoDe_w1th_B4sE64_aNd_XoR}
```  
Flag: ~~KCSC{eNcoDe_w1th_B4sE64_aNd_XoR}~~  
## Spy Room  
![image](https://hackmd.io/_uploads/BkdCyh5Dkl.png)  
đây là 1 bài dotnet đơn giản, không có gì phức tạp, chủ yếu là kiểm tra khả năng xài dnspy và cryptography cơ bản  
mở dnspy:  
![image](https://hackmd.io/_uploads/rJ3Dencwyl.png)  
bài flagchecker gọi khá nhiều hàm xor  
ta có thể dùng GPT gen chương trình decode :\(\(  
```python=
def xor(a, b):
    num = max(len(a), len(b))
    result = []
    for i in range(num):
        if len(a) >= len(b):
            result.append(chr(ord(a[i]) ^ ord(b[i % len(b)])))
        else:
            result.append(chr(ord(a[i % len(a)]) ^ ord(b[i])))
    return result

def reverse_xor(source, url):
    source_chars = [chr(e) for e in source]
    array6 = xor(source_chars, list(url))
    num = len(array6)
    array2 = array6[:num // 4]
    array3 = array6[num // 4:num // 2]
    array4 = array6[num // 2:3 * num // 4]
    array5 = array6[3 * num // 4:]
    array5 = xor(array5, array2)
    array4 = xor(array4, array5)
    array3 = xor(array3, array4)
    array2 = xor(array2, array3)

    decoded_array = array2 + array3 + array4 + array5
    return ''.join(decoded_array)

def main():
    source = [
        85, 122, 105, 71, 17, 94, 71, 24, 114, 78, 107, 11, 108, 106, 107, 113, 121, 51, 91, 117, 86, 110, 100, 
        18, 124, 104, 71, 66, 123, 3, 111, 99, 74, 107, 69, 77, 111, 2, 120, 125, 83, 99, 62, 99, 109, 76, 119, 
        111, 59, 32, 1, 93, 69, 117, 84, 106, 73, 85, 112, 66, 114, 92, 61, 80, 80, 104, 111, 72, 98, 28, 88, 
        94, 27, 120, 15, 76, 15, 67, 86, 117, 81, 108, 18, 37, 34, 101, 104, 109, 23, 30, 62, 78, 88, 10, 2, 63, 
        43, 72, 102, 38, 76, 23, 34, 62, 21, 97, 1, 97
    ]
    url = "https://www.youtube.com/watch?v=L8XbI9aJOXk"
    decoded_text = reverse_xor(source, url)
    
    print(decoded_text)

if __name__ == "__main__":
    main()
#VXpCT1ZGRXpkRVpaV0U0MVdEQldkVmt6U2pWalNGSndZakkxWmxZeWJEQmhSamxGWWpOU1QxSldVbVpWU0VwMldqTkthR0pVYjNwbVVUMDk=
```
output là chuỗi đã bị mã hóa base64 nhiều lần  
![image](https://hackmd.io/_uploads/Bkpn7h5PJx.png)  
Flag : ~~KCSC{Easy_Encryption_With_DotNET_Program:3}~~  
## EzRev  
![image](https://hackmd.io/_uploads/rypoEn9Pyg.png)  
Pseudocode IDA:  
```C=
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rdx
  unsigned int *v4; // r8
  int i; // [rsp+20h] [rbp-28h]
  __int64 v7; // [rsp+28h] [rbp-20h]

  sub_140001200("Enter Something: ", argv, envp);
  sub_1400012D0("%s", byte_1400047A8);
  if ( (unsigned int)sub_140001100(byte_1400047A8) == -1982483102 )
  {
    v7 = -1i64;
    do
      ++v7;
    while ( byte_1400047A8[v7] );
    if ( v7 == 40 )
    {
      sub_140001000(byte_1400047A8);
      dword_1400047A0 = 1;
      for ( i = 0; i < 40; ++i )
      {
        v4 = dword_140004700;
        v3 = dword_140004700[i];
        if ( dword_140004080[i] != (_DWORD)v3 )
          dword_1400047A0 = 0;
      }
    }
  }
  if ( dword_1400047A0 )
    sub_140001200("Excellent!! Here is your flag: KCSC{%s}", byte_1400047A8);
  else
    sub_140001200("You're chicken!!!", v3, v4);
  return 0;
}
```
phân tích sơ qua thì đây có thể là 1 bài flagchecker với một số hàm mã hóa cơ bản  
lần 1:  
![image](https://hackmd.io/_uploads/rJW5H25Pkx.png)  
chương trình nhận vào input và kiểm tra 1 điều kiện gì đấy  
![image](https://hackmd.io/_uploads/Bks0HhqvJe.png)

qua kiểm tra thì đây có thể là một loại hash nào đấy  
vì không thể dịch ngược được và không ảnh hưởng quá nhiều đến chương trình nên mình sẽ patch luôn tại đây để bỏ qua bước kiểm tra điều kiện này  
![image](https://hackmd.io/_uploads/BkuPP2qPyx.png)  
lần 2:  
![image](https://hackmd.io/_uploads/H12m_35Pkl.png)  
đếm số phần tử có trong ```byte_7FF64BE347A8``` (là input ta nhập vào) và kiểm tra xem có đủ 40 ký tự không  
gọi hàm ```sub_7FF64BE31000``` để mã hóa  
![image](https://hackmd.io/_uploads/HJjlY2cvJe.png)  
hàm ```sub_7FF64BE31000``` lấy từng bytes của input rồi xor với các phép toán dịch bit ROR, ROL nhiều lần rồi lưu các giá trị đó vào ```dword_7FF64BE34700```  
Cuối cùng là kiểm tra từng phần tử (dword) trong mảng ```dword_7FF64BE34700``` và ```dword_7FF64BE34080``` với nhau:  
![image](https://hackmd.io/_uploads/BkfI9hcP1e.png)  
Tổng kết:  
\- kiểm tra hash (bỏ qua)  
\- mã hóa qua hàm ```sub_7FF64BE31000```  
\- kiểm tra  
do mã hóa từng bytes một nên mình sẽ bruteforce luôn để tiết kiệm thời gian dịch ngược  
Script solve:  
```python=
def _rol(val, bits, bit_size=32):
    return (val << bits % bit_size) & (2 ** bit_size - 1) | ((val & (2 ** bit_size - 1)) >> (bit_size - (bits % bit_size)))
def _ror(val, bits, bit_size=32):
    return ((val & (2 ** bit_size - 1)) >> bits % bit_size) | (val << (bit_size - (bits % bit_size)) & (2 ** bit_size - 1))

def sub_7FF765091000(a1):
    for i in range(len(a1)):
        v2 = a1[i] 
        v5 = 4
        v6 = 6
        for j in range(5):
            v2 ^= _rol(v2, v5) ^ _ror(v2, v6)
            v5 *= 2
            v6 *= 2
        
    
    return (v2)
enc=[
    0x0F30C0330, 0x340DDE9D, 0x750D9AC9, 0x391FBC2A, 0x9F16AF5B, 0x0E6180661,
    0x6C1AAC6B, 0x340DDE9D, 0x0B60D5635, 0x9F16AF5B, 0x0A3195364, 0x681BBD3A,
    0x0F30C0330, 0x0A3195364, 0x0AB1B71C6, 0x0F30C0330, 0x0F21D5274, 0x9F16AF5B,
    0x0E6180661, 0x300CCFCC, 0x0F21D5274, 0x9F16AF5B, 0x0AB1B71C6, 0x0A3195364,
    0x750D9AC9, 0x0A3195364, 0x9F16AF5B, 0x0F21D5274, 0x0F30C0330, 0x0A3195364,
    0x0F21D5274, 0x351C8FD9, 0x710C8B98, 0x0F70D1261, 0x2D1AE83F, 0x0F30C0330,
    0x0EE1A24C3, 0x0F70D1261, 0x6108CEDC, 0x6108CEDC
]
flag=''
for e in enc:
    for i in range(33,127):
        a=sub_7FF765091000((flag+chr(i)).encode())
        if a==e:
            flag=flag+chr(i)
            print(flag)
            break
        
#345y_fl46_ch3ck3r_f0r_kc5c_r3cru17m3n7!!
```
Mình có tham khảo script chuyển ROR,ROL sang python tại: https://github.com/tandasat/scripts_for_RE/blob/master/rotate.py  
Flag: ~~KCSC{345y_fl46_ch3ck3r_f0r_kc5c_r3cru17m3n7!!}~~  
  
  
Thông thường mình sẽ không quá để ý việc dịch ngược hay chuyển code sang python cho những bài flagchecker như này mà sẽ hay xài gdb để bruteforce nhanh flag.  
Tuy nhiên lần này gdb không decompile được nên mình đã không thể xài lại trick cũ, đây cũng là bài học cho mình để thay đổi tư duy làm bài và nghiên cứu nghiêm túc hơn trong tương lai!  
có thể tham khảo 1 số bài mình đã giải bằng gdb tại: https://hackmd.io/@robertowen/rkXtc16N1l  
## Reverse me  
![image](https://hackmd.io/_uploads/rkoFZpqv1g.png)  
Pseudocode (khá dễ nhìn):  
```C=
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int i; // [rsp+18h] [rbp-58h]
  int j; // [rsp+1Ch] [rbp-54h]
  char s[56]; // [rsp+30h] [rbp-40h] BYREF
  unsigned __int64 v7; // [rsp+68h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  memset(s, 0, 0x31uLL);
  printf("FLAG: ");
  __isoc99_scanf("%48s", s);
  for ( i = 0; i <= 47; i += 8 )
    sub_12D4(&s[i], &s[i + 4]);
  for ( j = 0; ; ++j )
  {
    if ( j > 47 )
    {
      puts("Correct!");
      return 0LL;
    }
    if ( s[j] != byte_4040[j] )
      break;
  }
  puts("Incorrect!");
  return 0LL;
}
```
Vì mình không cài IDA lên WSL nên mình sẽ debug remote như này  
![image](https://hackmd.io/_uploads/Byopza9vkl.png)  
![image](https://hackmd.io/_uploads/r1mQXTcDkg.png)  
Do chương trình cũng đơn giản nên ta chỉ phân tích nhanh  
![image](https://hackmd.io/_uploads/BkGpQa9Dyg.png)  
\- chương trình nhận vào 48 bytes từ  input và mã hóa thông qua hàm ```sub_5555555552D4```, lưu trữ luôn vào s  
\- kiểm tra với ```byte_555555558040```, nếu đúng thì trả về Correct, sai thì Incorrect  
Hàm mã hóa ```sub_5555555552D4```:  
![image](https://hackmd.io/_uploads/SkCfSacvJl.png)  
ta có thể nhận ra đây là mã hóa XTEA khá quen thuộc  
Mình có tham khảo chương trình decrypt XTEA bằng python tại: https://github.com/niklasb/ctf-tools/blob/master/crypto/xtea.py  
Script:  
```python=
from Crypto.Util.number import*
dword_5555555580C0=[0x126575B, 0x51903231, 0x8AAB8F5E, 0x0CA51930F]
byte_555555558040=[473413356, 2967692918, 1094173039, 1162692205, 2047540795, 593189689, 3392237974, 2109325366, 3133376540, 144254372, 4264188329, 2498107430]
rounds = 32
mask = 0xffffffff
delta = 0x9E3779B9
def decrypt(v, key):
    v=list(v)
    sum=(delta*rounds)&mask
    for _ in range(rounds):
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum>>11) & 3])
        v[1] &= mask
        sum = (sum-delta)&mask
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3])
        v[0] &= mask
    return v
if __name__ == "__main__":
    n=b''
    for j in range(0,len(byte_555555558040),2):
        a=(decrypt(byte_555555558040[j:j+2], dword_5555555580C0))
        for i in range(2):
            n+=(long_to_bytes(a[i])[::-1])
    print(n)
#b'\xec\xb0LNQ\xa7r\xdd}\x1d\x0c\x9c\x0f\x9e\x93\x8ez\xb6\x1d\xedC\xea{H\xa93\x9f\x1a\rj\xa9\xc9m\xb5\xbc\xf1%\xc6\xb6.\x80,II\x1e\xb3\x103'
```
đến đây mình mới phát hiện ra điều gì đấy không đúng, ngồi fix lại chương trình decrypt khá lâu vì nghĩ chắc là sai ở đâu đấy, cuối cùng mình đã phải xem xét lại kỹ file binary  
![image](https://hackmd.io/_uploads/r1bbKaqPyl.png)  
trong functions mình thấy chương trình có gọi ```ptrace``` \- là syscall chống debug trong Linux  
do đây không phải là file Windows excutable nên sẽ không có các WinAPI như ```IsDebuggerPresent()``` hay ```NtQueryInformationProcess()``` nên ta cần lưu ý khi làm bài  
ta trỏ đến địa chỉ gọi ptrace:  
![image](https://hackmd.io/_uploads/SyZOjTqv1g.png)  
Nếu ta debug thì chương trình sẽ chuyển sang luồng fake, dẫn đến key decrypt XTEA bị sai  
xem pseudo code để có cái nhìn trực quan hơn:  
![image](https://hackmd.io/_uploads/rJBOna9PJe.png)  
ta có thể nhận thấy khác nhau ở ```off_555555558080``` và ```off_555555558090``` giữa luồng fake và luồng real dẫn đến chương trình trả về 2 key khác nhau  
cần sửa ZF hoặc patch để chương trình đưa vào luồng đúng  
lúc này ta có thể lấy ```dword_5555555580C0``` chuẩn ra và bỏ vào script solve:  
```python=
from Crypto.Util.number import*
#dword_5555555580C0=[0x126575B, 0x51903231, 0x8AAB8F5E, 0x0CA51930F]
dword_5555555580C0=[
    0x3AB27278,
    0x0A840805B,
    0x0E864925B,
    0x0B7B1EEDE]
byte_555555558040=[473413356, 2967692918, 1094173039, 1162692205, 2047540795, 593189689, 3392237974, 2109325366, 3133376540, 144254372, 4264188329, 2498107430] #dword
rounds = 32
mask = 0xffffffff
delta = 0x9E3779B9
def decrypt(v, key):
    v=list(v)
    sum=(delta*rounds)&mask
    for _ in range(rounds):
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum>>11) & 3])
        v[1] &= mask
        sum = (sum-delta)&mask
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3])
        v[0] &= mask
    return v
if __name__ == "__main__":
    n=b''
    for j in range(0,len(byte_555555558040),2):
        a=(decrypt(byte_555555558040[j:j+2], dword_5555555580C0))
        for i in range(2):
            n+=(long_to_bytes(a[i])[::-1])
    print(n)
#b'KCSC{XTEA_encryption_and_debugger_detection_:>>}'
```
Flag: ~~KCSC{XTEA_encryption_and_debugger_detection_:>>}~~  
## ChaChaCha  
![image](https://hackmd.io/_uploads/rJfjf09Dkl.png)  
Bài này mình tốn cả chiều để viết script decrypt tuy nhiên cuối cùng mình lại giải được mà không cần decrypt \:\(\( làm mình khá đuối sức và buồn ngủ  
  
![image](https://hackmd.io/_uploads/Bkf4N09vyl.png)  
Để cho ta 3 file, 1 file dump, 1 file txt và 1 file exe  
mở important_note.txt bằng hex editor và nhìn kích thước file thì ta có thể đoán rằng đây là 1 file đã bị mã hóa:  
![image](https://hackmd.io/_uploads/rJrCEC9P1e.png)  
mở file ChaChaCha.exe bằng IDA ta có pseudo code như sau:  
```C=
int __cdecl main(int argc, const char **argv, const char **envp)
{
  HMODULE LibraryA; // eax
  BOOLEAN (__stdcall *SystemFunction036)(PVOID, ULONG); // eax
  HMODULE v5; // eax
  BOOLEAN (__stdcall *ProcAddress)(PVOID, ULONG); // eax
  HANDLE FileW; // eax
  void *v8; // ebx
  signed int FileSize; // edi
  _BYTE *v11; // ebx
  int v12; // ecx
  _BYTE *v13; // ecx
  signed int v14; // esi
  signed int v15; // ebx
  _BYTE *v16; // eax
  char v17; // al
  char v18; // [esp+0h] [ebp-D8h]
  HANDLE hFile; // [esp+Ch] [ebp-CCh]
  signed int v20; // [esp+10h] [ebp-C8h]
  char *v21; // [esp+14h] [ebp-C4h]
  _BYTE *v22; // [esp+18h] [ebp-C0h]
  char *v23; // [esp+1Ch] [ebp-BCh]
  DWORD NumberOfBytesWritten; // [esp+20h] [ebp-B8h] BYREF
  DWORD NumberOfBytesRead; // [esp+24h] [ebp-B4h] BYREF
  char v26[48]; // [esp+28h] [ebp-B0h] BYREF
  int v27; // [esp+58h] [ebp-80h]
  char v28[64]; // [esp+68h] [ebp-70h] BYREF
  char v29[32]; // [esp+A8h] [ebp-30h] BYREF
  char v30[12]; // [esp+C8h] [ebp-10h] BYREF

  LibraryA = LoadLibraryA("advapi32.dll");
  SystemFunction036 = (BOOLEAN (__stdcall *)(PVOID, ULONG))GetProcAddress(LibraryA, "SystemFunction036");
  SystemFunction036(v29, 32);
  v5 = LoadLibraryA("advapi32.dll");
  ProcAddress = (BOOLEAN (__stdcall *)(PVOID, ULONG))GetProcAddress(v5, "SystemFunction036");
  ProcAddress(v30, 12);
  FileW = CreateFileW(FileName, 0xC0000000, 0, 0, 3u, 0x80u, 0);
  v8 = FileW;
  hFile = FileW;
  if ( FileW == (HANDLE)-1 )
  {
    sub_401590("Cannot Open File", v18);
    CloseHandle((HANDLE)0xFFFFFFFF);
    return 1;
  }
  else
  {
    FileSize = GetFileSize(FileW, 0);
    v20 = FileSize;
    v21 = (char *)malloc(FileSize);
    if ( ReadFile(v8, v21, FileSize, &NumberOfBytesRead, 0) )
    {
      v11 = malloc(FileSize);
      v22 = v11;
      sub_4013D0(v12, v30);
      v14 = 0;
      if ( FileSize > 0 )
      {
        v23 = v28;
        do
        {
          sub_401000(v26, v28, v13);
          ++v27;
          v15 = v14 + 64;
          if ( !__OFSUB__(v14, v14 + 64) )
          {
            v16 = v22;
            do
            {
              if ( v14 >= FileSize )
                break;
              v13 = &v16[v14];
              v17 = v23[v14] ^ v16[v14 + v21 - v22];
              ++v14;
              FileSize = v20;
              *v13 = v17;
              v16 = v22;
            }
            while ( v14 < v15 );
          }
          v23 -= 64;
          v14 = v15;
        }
        while ( v15 < FileSize );
        v11 = v22;
      }
      SetFilePointer(hFile, 0, 0, 0);
      if ( WriteFile(hFile, v11, FileSize, &NumberOfBytesWritten, 0) )
      {
        CloseHandle(hFile);
        sub_401590("Some important file has been encrypted!!!\n", (char)FileName);
        return 0;
      }
      else
      {
        sub_401590("Cannot Write File", v18);
        CloseHandle(hFile);
        return 1;
      }
    }
    else
    {
      sub_401590("Cannot Read File", v18);
      CloseHandle(v8);
      return 1;
    }
  }
}
```
phân tích:  
Đầu tiên chương trình tạo 1 Buffer ngẫu nhiên 32 bytes và 1 Buffer 12 bytes:  
![image](https://hackmd.io/_uploads/rJaHU0qwkx.png)  
  
tiếp đến là các bước mở file, đọc file gì đấy tuy nhiên mình sẽ không đi phân tích phần này:  
![image](https://hackmd.io/_uploads/BkFyvCqD1e.png)  
  
tiếp đến gọi hàm ```sub_8913D0```:  
![image](https://hackmd.io/_uploads/S15Uw0qvJx.png)  
Bên trong có khá nhiều phép toán bitwise, có thể là thuật toán tạo khóa nào đấy:  
![image](https://hackmd.io/_uploads/SkdiwR9vkx.png)  
ta để ý:  
```python!
qmemcpy(a2, "expand 32-byte k", 16);
```
đây có thể là gọi sig của mã hóa salsa20 hoặc chacha20, tuy nhiên đề bài là ChaChaCha nên khả năng cao là chacha20  
  
Ta có thể hiểu là tạo ma trận 4x4, hàng 1 là chuỗi “expand 32-byte k”, 2 hàng tiếp theo là 32 bytes key, 4 bytes đầu tiên của hàng cuối là counter = 1129530187 = 'KCSC' và 12 bytes cuối là nonce  
![image](https://hackmd.io/_uploads/ByOGqCcvyl.png)  
tìm hiểu thêm tại https://xilinx.github.io/Vitis_Libraries/security/2019.2/guide_L1/internals/chacha20.html  
đặt breakpoint như sau và mở hexview, ta có thể thấy key và nonce đã được lưu trữ:  
![image](https://hackmd.io/_uploads/ryH1JysD1x.png)  

tiếp theo:  
![image](https://hackmd.io/_uploads/BJdLo0cvyg.png)  
gọi hàm ```sub_891000``` là mã hóa file bằng thuật toán chacha20  
sau đó là xor gì đấy mình không hiểu lắm, có lẽ đây là nguyên nhân khiến mình viết chương trình decrypt cả chiều không được (sau khi tham khảo các WU khác thì thấy mọi người sử dụng CyberChef để decrypt)  
Tạm dừng ở đây, ta sẽ phân tích file dump:  
search strings "expand 32-byte k" trong IDA:  
![image](https://hackmd.io/_uploads/Sy5UkyoDJx.png)  
click vào để tìm địa chỉ lưu nó:  
![image](https://hackmd.io/_uploads/BJLt1yiwJl.png)  
Do file dump này trích được memory lúc file bị mã hóa thành important_note.txt nên đây sẽ là key và nonce để decrypt file  
dump lấy bytes:  
```
[0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33, 0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B, 0xD9, 0xFA, 0xBB, 0x42, 0x0C, 0x2D, 0xB8, 0x08, 0xD1, 0xF8, 0xBF, 0xA5, 0x89, 0x0A, 0xC3, 0xB3, 0x84, 0x9F, 0x69, 0xE2, 0xF3, 0x30, 0xD4, 0xA9, 0x0D, 0xB1, 0x19, 0xBD, 0x4E, 0xA0, 0xB8, 0x30, 0x4B, 0x43, 0x53, 0x43, 0xDB, 0x7B, 0xE6, 0x93, 0xEE, 0x9B, 0xC1, 0xA4, 0x70, 0x73, 0xCA, 0x4B]
```  
Do chacha20 có thể dùng chương trình mã hóa để giải mã(mã dòng), nên mình sẽ patch luôn bộ nhớ tại key hiện tại thành key lấy từ file dump để giải mã file important_note.txt  
đặt breakpoint tại:  
![image](https://hackmd.io/_uploads/ryH1JysD1x.png)  
ta chạy script sau để thay đổi thay đổi bộ nhớ (không thấy ai xài cách này nên tâm đắc vl 😈)  
```python=
import idaapi
import idc
start_addr = 0x00AFFAA0#địa chỉ sẽ khác nhau mỗi lần debug, cần thay đổi khi thử chạy
end_addr = start_addr+63
new_data = [
    0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33, 0x32, 0x2D, 0x62, 0x79,
    0x74, 0x65, 0x20, 0x6B, 0xD9, 0xFA, 0xBB, 0x42, 0x0C, 0x2D, 0xB8, 0x08,
    0xD1, 0xF8, 0xBF, 0xA5, 0x89, 0x0A, 0xC3, 0xB3, 0x84, 0x9F, 0x69, 0xE2,
    0xF3, 0x30, 0xD4, 0xA9, 0x0D, 0xB1, 0x19, 0xBD, 0x4E, 0xA0, 0xB8, 0x30,
    0x4B, 0x43, 0x53, 0x43, 0xDB, 0x7B, 0xE6, 0x93, 0xEE, 0x9B, 0xC1, 0xA4,
    0x70, 0x73, 0xCA, 0x4B
]

for i in range(len(new_data)):
    addr = start_addr + i
    idc.patch_byte(addr, new_data[i])
print(f"Thay đổi bộ nhớ thành công từ {hex(start_addr)} đến {hex(end_addr)}")

```
sau khi thay đổi bộ nhớ, tiếp tục chạy hết chương trình để mã hóa lại file  
mở lại file important_note.txt lúc nãy ra, ta thấy file đã được decrypt thành công  
![image](https://hackmd.io/_uploads/Syo07Jiwkl.png)  
Nhìn header ta có thể thấy đây là một file Windows excutable  
chạy file exe, ta được:  
![image](https://hackmd.io/_uploads/BJs4rkov1g.png)  
![image](https://hackmd.io/_uploads/HJQcryjPkl.png)  

## WaiterFall  
![image](https://hackmd.io/_uploads/rkcIRYoPkl.png)  
Mở IDA:  
![image](https://hackmd.io/_uploads/rk7OCFjvJx.png)  
nhìn có vẻ rất khủng bố :O  
Tuy nhiên đây chỉ là 1 dạng bài sử dụng Z3 rất kinh điển  
solve Script: (byClaude)  
```python=
from z3 import *

def solve_challenge():
    s = Solver()
    chars = [BitVec(f'char_{i}', 8) for i in range(62)]
    v3 = 0
    
    v5 = 0x1000008020020
    v7 = 0x60010020000100
    v8 = 0x100020080408000
    v9 = 0x844000044000
    for i, char in enumerate(chars):
        s.add(char >= 32)  # Space
        s.add(char <= 126)  # ~        
        conditions = []
        conditions.append(If(char == ord('C'), If((i - 1) & 0xFFFFFFFD == 0, 1, 0), 0))
        conditions.append(If(char == ord('K'), If(i == 0, 1, 0), 0))
        conditions.append(If(char == ord('S'), If(i == 2, 1, 0), 0))
        conditions.append(If(char == ord('c'), If(i == 37, 1, 0), 0))
        conditions.append(If(char == ord('d'), If(i == 20, 1, 0), 0))
        conditions.append(If(char == ord('g'), If(Or(i == 11, i == 60), 1, 0), 0))
        conditions.append(If(char == ord('u'), If(i == 24, 1, 0), 0))
        conditions.append(If(char == ord('{'), If(i == 4, 1, 0), 0))
        conditions.append(If(char == ord('}'), If(i == 61, 1, 0), 0))
        
        if i <= 0x31:  # For '_'
            if (0x2101004011000 >> i) & 1:
                conditions.append(If(char == ord('_'), 1, 0))
        
        if i <= 0x34:  # For 'a'
            if (0x10000210000040 >> i) & 1:
                conditions.append(If(char == ord('a'), 1, 0))
                
        if i <= 0x37:  # For 'e'
            if (0x80000040200000 >> i) & 1:
                conditions.append(If(char == ord('e'), 1, 0))
                
        if i <= 0x32:  # For 'f'
            if (0x4200100802000 >> i) & 1:
                conditions.append(If(char == ord('f'), 1, 0))
                
        if i <= 0x3A:  # For 'i'
            if (0x400000000000280 >> i) & 1:
                conditions.append(If(char == ord('i'), 1, 0))
                
        if i <= 0x33:  # For 'l'
            if (0x8480C02000000 >> i) & 1:
                conditions.append(If(char == ord('l'), 1, 0))
                
        if i <= 0x3B:  # For 'n'
            if (0xA00008000080400 >> i) & 1:
                conditions.append(If(char == ord('n'), 1, 0))
                
        if i <= 0x2F:  # For 'o'
            if (v9 >> i) & 1:
                conditions.append(If(char == ord('o'), 1, 0))
                
        if i <= 0x38:  # For 'r'
            if (v8 >> i) & 1:
                conditions.append(If(char == ord('r'), 1, 0))
                
        if i <= 0x36:  # For 't'
            if (v7 >> i) & 1:
                conditions.append(If(char == ord('t'), 1, 0))
                
        if i <= 0x30:  # For 'w'
            if (v5 >> i) & 1:
                conditions.append(If(char == ord('w'), 1, 0))        
        v3 = v3 + Sum(conditions)
    s.add(v3 == 62)
    
    if s.check() == sat:
        m = s.model()
        result = ''
        for i in range(62):
            c = m[chars[i]].as_long()
            result += chr(c)
        return result
    return None

result = solve_challenge()
if result:
    print("Flag:", result)
else:
    print("No solution found")
#Flag: KCSC{waiting_for_wonderful_waterfall_control_flow_flatterning}
```
Flag: ~~KCSC{waiting_for_wonderful_waterfall_control_flow_flatterning}~~  
## STEAL  
bao giờ mình thật sự hiểu bài thì may ra mới viết được :\(\(  
# Crypto  
:((  