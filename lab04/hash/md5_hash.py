def left_rotate(value, shift):
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

def md5(message):
   
    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476
    

    original_length = len(message) * 8 
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += original_length.to_bytes(8, 'little')
    
  
    for i in range(0, len(message), 64):
        block = message[i:i+64]
        
        words = [int.from_bytes(block[j:j+4], 'little') for j in range(0, 64, 4)]
        

        aa = a
        bb = b
        cc = c
        dd = d
        

        for j in range(64):
            if j < 16:
                f = (b & c) | ((~b) & d)
                g = j
            elif j < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * j + 1) % 16
            elif j < 48:
                f = b ^ c ^ d
                g = (3 * j + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * j) % 16
            
           
            temp = d
            d = c
            c = b
            b = b + left_rotate((a + f + 0x5A827999 + words[g]) & 0xFFFFFFFF, 3)
            a = temp
        
       
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    

    return '{:08x}{:08x}{:08x}{:08x}'.format(a, b, c, d)


input_string = input("Nhập chuỗi căn bản: ")
md5_hash = md5(input_string.encode('utf-8'))
print("Mã băm MD5 của chuỗi '{}' là: {}".format(input_string, md5_hash))