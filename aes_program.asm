; multi-segment executable file template.

data segment 
;///////////////////////////////////////////
;these vars are for the encryption!!
;///////////////////////////////////////////
multiply db 02H,03H,01H,01H,01H,02H,03H,01H,01H,01H,02H,03H,03H,01H,01H,02H

HEX db  '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
Last_hex db 64 dup('!') 
temp_message db 18 dup('!')      
true_message db 16 dup(0)

allroundkeys db 160 dup('!')

outp db " In Hex==>$"

temp_key db 18 dup('!')  
             
true_key db 16 dup(0)  

Arranged_Message db 16 dup(0)
  
Arranged_Key db 16 dup(0)

tempcol db 4 dup(0)
aftermix db 16 dup(0)

Final db 02H,03H,01H,01H,01H,02H,03H,01H,01H,01H,02H,03H,03H,01H,01H,02H ;17 dup('!')                                        
 
RCON DB 01H,02H,04H,08H,10H,20H,40H,80H,1BH,36H,00h  ;00h is for preventing overflow
COPY1 DB 16 DUP('!')
                                       
temp db 4 dup(?)
                                        
SBOX DB 63H,7CH,77H,7BH,0F2H,6BH,6FH,0C5H,30H,01H,67H,2BH,0FEH,0D7H,0ABH,76H
DB 0CAH,82H,0C9H,7DH,0FAH,59H,47H,0F0H,0ADH,0D4H,0A2H,0AFH,9CH,0A4H,72H,0C0H
DB 0B7H,0FDH,93H,26H,36H,3FH,0F7H,0CCH,34H,0A5H,0E5H,0F1H,71H,0D8H,31H,15H
DB 04H,0C7H,23H,0C3H,18H,96H,05H,9AH,07H,12H,80H,0E2H,0EBH,27H,0B2H,75H
DB 09H,83H,2CH,1AH,1BH,6EH,5AH,0A0H,52H,3BH,0D6H,0B3H,29H,0E3H,2FH,84H
DB 53H,0D1H,00H,0EDH,20H,0FCH,0B1H,5BH,6AH,0CBH,0BEH,39H,4AH,4CH,58H,0CFH
DB 0D0H,0EFH,0AAH,0FBH,43H,4DH,33H,85H,45H,0F9H,02H,7FH,50H,3CH,9FH,0A8H
DB 51H,0A3H,40H,8FH,92H,9DH,38H,0F5H,0BCH,0B6H,0DAH,21H,10H,0FFH,0F3H,0D2H
DB 0CDH,0CH,13H,0ECH,5FH,97H,44H,17H,0C4H,0A7H,7EH,3DH,64H,5DH,19H,73H
DB 60H,81H,4FH,0DCH,22H,2AH,90H,88H,46H,0EEH,0B8H,14H,0DEH,5EH,0BH,0DBH
DB 0E0H,32H,3AH,0AH,49H,06H,24H,5CH,0C2H,0D3H,0ACH,62H,91H,95H,0E4H,79H
DB 0E7H,0C8H,37H,6DH,8DH,0D5H,4EH,0A9H,6CH,56H,0F4H,0EAH,65H,7AH,0AEH,08H
DB 0BAH,78H,25H,2EH,1CH,0A6H,0B4H,0C6H,0E8H,0DDH,74H,1FH,4BH,0BDH,8BH,8AH
DB 70H,3EH,0B5H,66H,48H,03H,0F6H,0EH,61H,35H,57H,0B9H,86H,0C1H,1DH,9EH
DB 0E1H,0F8H,98H,11H,69H,0D9H,8EH,94H,9BH,1EH,87H,0E9H,0CEH,55H,28H,0DFH
DB 8CH,0A1H,89H,0DH,0BFH,0E6H,42H,68H,41H,99H,2DH,0FH,0B0H,54H,0BBH,16H 
;//////////////////////INTERFACE-///////////





kp db "  Please Insert Secret Key==>$" 
mp db "  Please Enter a Block To Encrypt==>$" 

cp db "  Please Insert Secret Key==>$"
xp db "  Please Enter The CipherText==>$"

;//////////////////////////////////////////////////////////////////////////////////////////////////
;thse vars are for the decryption!!////////////////////////////////////////////////////////////////
;//////////////////////////////////////////////////////////////////////////////////////////////////
;//////////////////////////////////////////////////////////////////////////////////////////////////

inverse_sbox db 052h, 09h,  06ah, 0d5h, 030h, 036h, 0a5h, 038h, 0bfh, 040h, 0a3h, 09eh, 081h, 0f3h, 0d7h, 0fbh,
           db 07ch, 0e3h, 039h, 082h, 09bh, 02fh, 0ffh, 087h, 034h, 08eh, 043h, 044h, 0c4h, 0deh, 0e9h, 0cbh,
           db 054h, 07bh, 094h, 032h, 0a6h, 0c2h, 023h, 03dh, 0eeh, 04ch, 095h, 00bh, 042h, 0fah, 0c3h, 04eh,
           db 008h, 02eh, 0a1h, 066h, 028h, 0d9h, 024h, 0b2h, 076h, 05bh, 0a2h, 049h, 06dh, 08bh, 0d1h, 025h,
           db 072h, 0f8h, 0f6h, 064h, 086h, 068h, 098h, 016h, 0d4h, 0a4h, 05ch, 0cch, 05dh, 065h, 0b6h, 092h,
           db 06ch, 070h, 048h, 050h, 0fdh, 0edh, 0b9h, 0dah, 05eh, 015h, 046h, 057h, 0a7h, 08dh, 09dh, 084h,
           db 090h, 0d8h, 0abh, 000h, 08ch, 0bch, 0d3h, 00ah, 0f7h, 0e4h, 058h, 005h, 0b8h, 0b3h, 045h, 006h,
           db 0d0h, 02ch, 01eh, 08fh, 0cah, 03fh, 00fh, 002h, 0c1h, 0afh, 0bdh, 003h, 001h, 013h, 08ah, 06bh,
           db 03ah, 091h, 011h, 041h, 04fh, 067h, 0dch, 0eah, 097h, 0f2h, 0cfh, 0ceh, 0f0h, 0b4h, 0e6h, 073h,
           db 096h, 0ach, 074h, 022h, 0e7h, 0adh, 035h, 085h, 0e2h, 0f9h, 037h, 0e8h, 01ch, 075h, 0dfh, 06eh,
           db 047h, 0f1h, 01ah, 071h, 01dh, 029h, 0c5h, 089h, 06fh, 0b7h, 062h, 00eh, 0aah, 018h, 0beh, 01bh,
           db 0fch, 056h, 03eh, 04bh, 0c6h, 0d2h, 079h, 020h, 09ah, 0dbh, 0c0h, 0feh, 078h, 0cdh, 05ah, 0f4h,
           db 01fh, 0ddh, 0a8h, 033h, 088h, 007h, 0c7h, 031h, 0b1h, 012h, 010h, 059h, 027h, 080h, 0ech, 05fh,
           db 060h, 051h, 07fh, 0a9h, 019h, 0b5h, 04ah, 00dh, 02dh, 0e5h, 07ah, 09fh, 093h, 0c9h, 09ch, 0efh,
           db 0a0h, 0e0h, 03bh, 04dh, 0aeh, 02ah, 0f5h, 0b0h, 0c8h, 0ebh, 0bbh, 03ch, 083h, 053h, 099h, 061h,
           db 017h, 02bh, 004h, 07eh, 0bah, 077h, 0d6h, 026h, 0e1h, 069h, 014h, 063h, 055h, 021h, 00ch, 07dh 
           
            
temp_ciphertext db 18 dup('*')
ciphertext db 16 dup('!')
temp_cipherkey db 18 dup ('*')
cipherkey db 16 dup('#')

Arranged_Ciphertext db 29h, 57h, 40h, 1Ah, 0C3h, 14h, 22h, 02h, 50h, 20h, 99h, 0D7h, 5Fh, 0F6h, 0B3h, 3Ah
Arranged_cipherkey db 16 dup('!')
save_inputed_cupherkey db 16 dup('!')


;/////////////////////////////inverse mix columns+rijndals multipication matrixes//////////////////
afterinversemix db 16 dup('!')
inverse_tempcol db 4 dup('!')
inverse_multiply db 0Eh ,0Bh, 0Dh, 09h,09h, 0Eh, 0Bh, 0Dh,0Dh,09h ,0Eh ,0Bh,0Bh, 0Dh, 09h, 0Eh





multiply_9 db 000h,009h,012h,01bh,024h,02dh,036h,03fh,048h,041h,05ah,053h,06ch,065h,07eh,077h,
           db 090h,099h,082h,08bh,0b4h,0bdh,0a6h,0afh,0d8h,0d1h,0cah,0c3h,0fch,0f5h,0eeh,0e7h,
           db 03bh,032h,029h,020h,01fh,016h,00dh,004h,073h,07ah,061h,068h,057h,05eh,045h,04ch,
           db 0abh,0a2h,0b9h,0b0h,08fh,086h,09dh,094h,0e3h,0eah,0f1h,0f8h,0c7h,0ceh,0d5h,0dch,
           db 076h,07fh,064h,06dh,052h,05bh,040h,049h,03eh,037h,02ch,025h,01ah,013h,008h,001h,
           db 0e6h,0efh,0f4h,0fdh,0c2h,0cbh,0d0h,0d9h,0aeh,0a7h,0bch,0b5h,08ah,083h,098h,091h,
           db 04dh,044h,05fh,056h,069h,060h,07bh,072h,005h,00ch,017h,01eh,021h,028h,033h,03ah,
           db 0ddh,0d4h,0cfh,0c6h,0f9h,0f0h,0ebh,0e2h,095h,09ch,087h,08eh,0b1h,0b8h,0a3h,0aah,	
           db 0ech,0e5h,0feh,0f7h,0c8h,0c1h,0dah,0d3h,0a4h,0adh,0b6h,0bfh,080h,089h,092h,09bh,	
           db 07ch,075h,06eh,067h,058h,051h,04ah,043h,034h,03dh,026h,02fh,010h,019h,002h,00bh,
           db 0d7h,0deh,0c5h,0cch,0f3h,0fah,0e1h,0e8h,09fh,096h,08dh,084h,0bbh,0b2h,0a9h,0a0h,
           db 047h,04eh,055h,05ch,063h,06ah,071h,078h,00fh,006h,01dh,014h,02bh,022h,039h,030h,
           db 09ah,093h,088h,081h,0beh,0b7h,0ach,0a5h,0d2h,0dbh,0c0h,0c9h,0f6h,0ffh,0e4h,0edh,
           db 00ah,003h,018h,011h,02eh,027h,03ch,035h,042h,04bh,050h,059h,066h,06fh,074h,07dh,	
           db 0a1h,0a8h,0b3h,0bah,085h,08ch,097h,09eh,0e9h,0e0h,0fbh,0f2h,0cdh,0c4h,0dfh,0d6h,
           db 031h,038h,023h,02ah,015h,01ch,007h,00eh,079h,070h,06bh,062h,05dh,054h,04fh,046h




multiply_11 db 000h,00bh,016h,01dh,02ch,027h,03ah,031h,058h,053h,04eh,045h,074h,07fh,062h,069h,
            db 0b0h,0bbh,0a6h,0adh,09ch,097h,08ah,081h,0e8h,0e3h,0feh,0f5h,0c4h,0cfh,0d2h,0d9h,
            db 07bh,070h,06dh,066h,057h,05ch,041h,04ah,023h,028h,035h,03eh,00fh,004h,019h,012h,
            db 0cbh,0c0h,0ddh,0d6h,0e7h,0ech,0f1h,0fah,093h,098h,085h,08eh,0bfh,0b4h,0a9h,0a2h,
            db 0f6h,0fdh,0e0h,0ebh,0dah,0d1h,0cch,0c7h,0aeh,0a5h,0b8h,0b3h,082h,089h,094h,09fh,
            db 046h,04dh,050h,05bh,06ah,061h,07ch,077h,01eh,015h,008h,003h,032h,039h,024h,02fh,
            db 08dh,086h,09bh,090h,0a1h,0aah,0b7h,0bch,0d5h,0deh,0c3h,0c8h,0f9h,0f2h,0efh,0e4h,
            db 03dh,036h,02bh,020h,011h,01ah,007h,00ch,065h,06eh,073h,078h,049h,042h,05fh,054h,
            db 0f7h,0fch,0e1h,0eah,0dbh,0d0h,0cdh,0c6h,0afh,0a4h,0b9h,0b2h,083h,088h,095h,09eh,
            db 047h,04ch,051h,05ah,06bh,060h,07dh,076h,01fh,014h,009h,002h,033h,038h,025h,02eh,
            db 08ch,087h,09ah,091h,0a0h,0abh,0b6h,0bdh,0d4h,0dfh,0c2h,0c9h,0f8h,0f3h,0eeh,0e5h,
            db 03ch,037h,02ah,021h,010h,01bh,006h,00dh,064h,06fh,072h,079h,048h,043h,05eh,055h,
            db 001h,00ah,017h,01ch,02dh,026h,03bh,030h,059h,052h,04fh,044h,075h,07eh,063h,068h,
            db 0b1h,0bah,0a7h,0ach,09dh,096h,08bh,080h,0e9h,0e2h,0ffh,0f4h,0c5h,0ceh,0d3h,0d8h,
            db 07ah,071h,06ch,067h,056h,05dh,040h,04bh,022h,029h,034h,03fh,00eh,005h,018h,013h,
            db 0cah,0c1h,0dch,0d7h,0e6h,0edh,0f0h,0fbh,092h,099h,084h,08fh,0beh,0b5h,0a8h,0a3h



  
  
multiply_13 db 000h,00dh,01ah,017h,034h,039h,02eh,023h,068h,065h,072h,07fh,05ch,051h,046h,04bh,
            db 0d0h,0ddh,0cah,0c7h,0e4h,0e9h,0feh,0f3h,0b8h,0b5h,0a2h,0afh,08ch,081h,096h,09bh,
            db 0bbh,0b6h,0a1h,0ach,08fh,082h,095h,098h,0d3h,0deh,0c9h,0c4h,0e7h,0eah,0fdh,0f0h,
            db 06bh,066h,071h,07ch,05fh,052h,045h,048h,003h,00eh,019h,014h,037h,03ah,02dh,020h,
            db 06dh,060h,077h,07ah,059h,054h,043h,04eh,005h,008h,01fh,012h,031h,03ch,02bh,026h,
            db 0bdh,0b0h,0a7h,0aah,089h,084h,093h,09eh,0d5h,0d8h,0cfh,0c2h,0e1h,0ech,0fbh,0f6h,
            db 0d6h,0dbh,0cch,0c1h,0e2h,0efh,0f8h,0f5h,0beh,0b3h,0a4h,0a9h,08ah,087h,090h,09dh,
            db 006h,00bh,01ch,011h,032h,03fh,028h,025h,06eh,063h,074h,079h,05ah,057h,040h,04dh,
            db 0dah,0d7h,0c0h,0cdh,0eeh,0e3h,0f4h,0f9h,0b2h,0bfh,0a8h,0a5h,086h,08bh,09ch,091h,
            db 00ah,007h,010h,01dh,03eh,033h,024h,029h,062h,06fh,078h,075h,056h,05bh,04ch,041h,
            db 061h,06ch,07bh,076h,055h,058h,04fh,042h,009h,004h,013h,01eh,03dh,030h,027h,02ah,
            db 0b1h,0bch,0abh,0a6h,085h,088h,09fh,092h,0d9h,0d4h,0c3h,0ceh,0edh,0e0h,0f7h,0fah,
            db 0b7h,0bah,0adh,0a0h,083h,08eh,099h,094h,0dfh,0d2h,0c5h,0c8h,0ebh,0e6h,0f1h,0fch,
            db 067h,06ah,07dh,070h,053h,05eh,049h,044h,00fh,002h,015h,018h,03bh,036h,021h,02ch,
            db 00ch,001h,016h,01bh,038h,035h,022h,02fh,064h,069h,07eh,073h,050h,05dh,04ah,047h,
            db 0dch,0d1h,0c6h,0cbh,0e8h,0e5h,0f2h,0ffh,0b4h,0b9h,0aeh,0a3h,080h,08dh,09ah,097h
















multiply_14 db 000h,00eh,01ch,012h,038h,036h,024h,02ah,070h,07eh,06ch,062h,048h,046h,054h,05ah,
            db 0e0h,0eeh,0fch,0f2h,0d8h,0d6h,0c4h,0cah,090h,09eh,08ch,082h,0a8h,0a6h,0b4h,0bah,
            db 0dbh,0d5h,0c7h,0c9h,0e3h,0edh,0ffh,0f1h,0abh,0a5h,0b7h,0b9h,093h,09dh,08fh,081h,
            db 03bh,035h,027h,029h,003h,00dh,01fh,011h,04bh,045h,057h,059h,073h,07dh,06fh,061h,
            db 0adh,0a3h,0b1h,0bfh,095h,09bh,089h,087h,0ddh,0d3h,0c1h,0cfh,0e5h,0ebh,0f9h,0f7h,
            db 04dh,043h,051h,05fh,075h,07bh,069h,067h,03dh,033h,021h,02fh,005h,00bh,019h,017h,
            db 076h,078h,06ah,064h,04eh,040h,052h,05ch,006h,008h,01ah,014h,03eh,030h,022h,02ch,
            db 096h,098h,08ah,084h,0aeh,0a0h,0b2h,0bch,0e6h,0e8h,0fah,0f4h,0deh,0d0h,0c2h,0cch,
            db 041h,04fh,05dh,053h,079h,077h,065h,06bh,031h,03fh,02dh,023h,009h,007h,015h,01bh,
            db 0a1h,0afh,0bdh,0b3h,099h,097h,085h,08bh,0d1h,0dfh,0cdh,0c3h,0e9h,0e7h,0f5h,0fbh,
            db 09ah,094h,086h,088h,0a2h,0ach,0beh,0b0h,0eah,0e4h,0f6h,0f8h,0d2h,0dch,0ceh,0c0h,
            db 07ah,074h,066h,068h,042h,04ch,05eh,050h,00ah,004h,016h,018h,032h,03ch,02eh,020h,
            db 0ech,0e2h,0f0h,0feh,0d4h,0dah,0c8h,0c6h,09ch,092h,080h,08eh,0a4h,0aah,0b8h,0b6h,
            db 00ch,002h,010h,01eh,034h,03ah,028h,026h,07ch,072h,060h,06eh,044h,04ah,058h,056h,
            db 037h,039h,02bh,025h,00fh,001h,013h,01dh,047h,049h,05bh,055h,07fh,071h,063h,06dh,
            db 0d7h,0d9h,0cbh,0c5h,0efh,0e1h,0f3h,0fdh,0a7h,0a9h,0bbh,0b5h,09fh,091h,083h,08dh


;////////////////////////////////////////////////////////////////////////////////////////
 ;//////////////////////////////////file reading vars ///////////////////////////////////////
 ;//////////////////////////////////////////////////////////////////////////////////////
intro1 db "This option will encryt a file with the given name using a given key$"
intro2 db "note that the text's bytes  must be divided by 16(n%16=0)$" 
intro22 db "If your file size cannot be divided by 16 just add 0$"
intro3 db "please create a file in the same directory that it's total name will be 7 chars$"
intro33 db "the encrypted file can be written in a random format and not only on ascii$"
intro332 db "you can easily convert the text to ascii, but the decimal value of it is the same$"
intro34 db   "An encrypted file will be stored in the same directory under the name:ENCRYPTE$" 
intro4 db "you can use the name 'aes.txt' for example$" 
intro5 db "after creating the file enter its name==>$"                     




temp_name db 10 dup('1')

file_name db 7 dup(0)

file_handle dw 1 dup(0)

file_data db 16 dup(0)

new_file db  "encrypted.txt";will be ENCRYPTE 
new_file_handle dw 1 dup(0) 
rounds db 1 dup(0)
safe_key db 16 dup(0) 

dune db "File encryption dune!$"


pick db "Hey, Please pick an option for aes using the  keyboard chars (a,e,d)$"
left db "e button: aes encryption$"
right db "d button: aes decryption$"
up db "f button: aes file encryption$"







ends






                                   
stack segment
    dw   128  dup(0)
ends


code segment 

      
      
      
      
      
      
      
   
   
      proc Clear_ALL_Registers
        xor ax,ax
        xor bx,bx
        xor cx,cx
        xor dx,dx
        xor si,si
        xor di,di
        xor bp,bp
        ret
      endp
       
       
       
       
       
       
       
    proc multiply2
        mov ax,[si]
        mov dx,02h 
        xor ah,ah
        mul dx
        cmp ah,0
        jz b1
        xor al,01bh
        b1:
        ret
    endp 
    
    
    
    
    
    
    
    
    
    proc multiply3
        mov ax,[si]
        mov dx,02h 
        xor ah,ah
        mul dx
        cmp ah,0
        jz b12
        xor ax,01bh
        b12:
        xor ax,[si]
        ret
        ;val in al
    endp
     
     
       
       
       
       
    proc multiply1
        mov ax,[si]
        ;take al
        ret 
        
    endp
    
    
    
    
    
    
    
    
    
     proc inserttotemp1
         push di
                                            
        mov di, offset Arranged_Message+1
        mov si,offset tempcol 
        mov cx,4
        run2:
        mov al,[di]
        mov [si],al 
        add di,4
        inc si
        loop run2
        pop di
        
        
        ret
     endp
           
           
           
           
           
       
       
       
           
           
           
      proc inserttotemp2
         push di
                                            
        mov di, offset Arranged_Message+2
        mov si,offset tempcol 
        mov cx,4
        run1:
        mov al,[di]
        mov [si],al 
        add di,4
        inc si
        loop run1
        pop di
        
        
        ret
      endp
           
           
           
           
           
           
           
        
        
        
        
        
           
       proc inserttotemp3
         push di
                                            
        mov di, offset Arranged_Message+3
        mov si,offset tempcol 
        mov cx,4
        run3:
        mov al,[di]
        mov [si],al 
        add di,4
        inc si
        loop run3
        pop di
        
        
        ret
       endp  
       
       
       
       
       
       
       
        
        
        
    proc inserttotemp
         push di
                                            
        mov di, offset Arranged_Message
        mov si,offset tempcol 
        mov cx,4
        run:
        mov al,[di]
        mov [si],al 
        add di,4
        inc si
        loop run
        pop di
        
        
        ret
    endp
    
       
       
       
       
       
       
       
       
    
    proc multiply_tempcol_once 
        
        cmp [di],1
        jz x
        cmp [di],2
        jz y
        cmp [di],3
        jz z
        x:
        call multiply1
        jmp eny
        y:
        call multiply2
        jmp eny
        z:
        call multiply3
        jmp eny
        eny:
         
        
        ret
    endp
         
         
         
         
         
         
         
         
         
    
    proc multiplyall 
        
        mov si, offset tempcol
         
        mov cx,4
        all:
        call multiply_tempcol_once
        mov [si],al
        inc si
        inc di
        loop all 
        
        ret
    endp
         
         
         
         
      
      
      
      
         
         
         
    proc xortempcol        
        
        mov si,offset tempcol 
        mov ax, [si]
        mov cx,3
        jj: 
        xor ax,[si+1]
        inc si
        loop jj
        ret 
        
        ;returns the value in al
    endp
    
      
      
      
      
      
      
   proc mixcol1 
     mov bp,4
     
     mov bx,offset aftermix
     ;mov cx,4
     
     firstcol: 
     call inserttotemp
     call multiplyall
     call xortempcol 
     mov [bx],al 
     add bx,4
     cmp bp,0
     dec bp
     jnz firstcol          
     ret
   endp 
     
      
      
      
      
      
      
      
     
   proc mixcol2
     mov bp,4 
     mov bx, offset aftermix+1
     seconedcol:
     call inserttotemp1
     call multiplyall
     ;mov di,offset multiply
     call xortempcol
     mov [bx],al
     add bx,4
     cmp bp,0
     dec bp
     jnz seconedcol
     ret
   endp
       
       
   proc mixcol3
     mov bp,4 
     mov bx, offset aftermix+2
     thirdcolumn:
     call inserttotemp2
     call multiplyall
     ;mov di,offset multiply
     call xortempcol
     mov [bx],al
     add bx,4
     cmp bp,0
     dec bp
     jnz thirdcolumn
     ret
   endp  
   
   
       
       
       
       
       
       
       
    proc mixcol4
     mov bp,4 
     mov bx, offset aftermix+3
     fourthcolumn:
     call inserttotemp3
     call multiplyall
     ;mov di,offset multiply
     call xortempcol
     mov [bx],al
     add bx,4
     cmp bp,0
     dec bp
     jnz fourthcolumn
     ret
   endp
    
      
      
      
      
      
      
      
      
    proc CopyAfterMix_ColumnsTotArranged_Message
        mov si,offset aftermix
        mov di,offset Arranged_Message
        mov cx,16
        copy:
        mov al,[si]
        mov [di],al
        inc si
        inc di
        loop copy
        ret
    endp
    
    
       
       
       
       
       
       
       
       
       
        
    proc Mix_Columns
         xor ax,ax
        xor bx,bx
        xor cx,cx
        xor dx,dx
        xor si,si
        xor di,di
        xor bp,bp
         mov di,offset multiply
         call mixcol1 
     
         mov di,offset multiply
         call mixcol2 
     
         mov di,offset multiply
         call mixcol3 
     
        mov di,offset multiply
        call mixcol4
        
        call CopyAfterMix_ColumnsTotArranged_Message  
        ret
    endp
    
    
     
    
    
   
   
   
   
      
     
    
    
    
    
        
    proc Keys_Expansion 
            xor ax,ax
            xor dx,dx
            xor si,si
            xor di,di
            xor cx,cx
            xor bx,bx
            mov di, offset Arranged_Key+3
            mov si, offset temp
            mov cx,4
            
            insert:
            mov bl,[di]
            mov [si],bl
            add di, 4
            inc si
            loop insert
            
            mov cx,3
            mov si, offset temp
            mov bl,[si]
            shift:
            mov al,[si+1]
            mov [si],al 
            inc si
            loop shift
            mov si, offset temp
            mov [si+3],bl
;           ;subbbytes
;           mov si,offset temp                       .
            mov di, offset sbox 
            xor ax,ax
            mov cx,4
            XOR AX,AX
           
            mov si,offset temp
            mov di, offset sbox
            mov cx,4 
            looop:
            mov al,[si]
            add di,ax
            mov bl,[di]
            mov [si],bl
            mov di,offset sbox
            inc si
            loop looop
;           rcon
            mov BX, offset rcon
            mov si,offset temp 
            mov ax,[si]
            xor al,[BX]
            mov [si],al
             
             
             
            ;xor with first
            mov di, offset Arranged_Key
            mov si, offset temp 
            mov cx,4
            col1:
            mov al ,[di]
            mov bl, [si]
            xor al,bl
            mov [di],al
            mov [si],al
            add di,4
            inc si
            loop col1 
            
            ;now temp holds first new col 
             
             
             ;xorscond
             mov di,offset Arranged_Key+1
             mov si,offset temp
             mov cx,4
             col2:
             mov al,[di]
             mov bl,[si]
             xor al,bl
             mov [di],al
             mov [si],al
             inc si
             add di,4
             loop col2
             ;xorthird
             mov di,offset Arranged_Key+2
             mov si,offset temp
             mov cx,4
             col3:
             mov al,[di]
             mov bl,[si]
             xor al,bl
             mov [di],al
             mov [si],al
             inc si
             add di,4
             loop col3
             ;xorfourth
             mov di,offset Arranged_Key+3
             mov si,offset temp
             mov cx,4
             col4:
             mov al,[di]
             mov bl,[si]
             xor al,bl
             mov [di],al
             mov [si],al
             inc si
             add di,4
             loop col4
             ret
          endp
             
             
             
             
             
             
             
            
             
       
       proc Arrange_Array_Key 
            xor ax,ax
            xor dx,dx
            xor si,si
            xor di,di
            xor cx,cx
            xor bx,bx
         mov si,offset true_key
         mov di, offset Arranged_Key
        mov cx,4
        l51:
        mov al,[si]
        mov [di],al
        inc si
        add di,4 
        loop l51
        
        
        mov cx,4
        mov di,offset Arranged_Key+1
        l61:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop l61
        
        mov cx,4
        mov di, offset Arranged_Key+2
        l71:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop l71
        
        mov cx,4
        mov di,offset Arranged_Key+3
        l81:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop l81
        ret
     endp
    
    
    
    
     
    
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
       
     proc Byte_Substitution
        xor ax,ax
        xor bx,bx
        xor cx,cx
        xor dx,dx
        xor si,si
        xor di,di
        xor bp,bp
        MOV CX,16
        mov si,offset Arranged_Message
        mov di, offset sbox
        mov cx,16 
        looop1:
        mov al,[si]
        add di,ax
        mov bl,[di]
        mov [si],bl
        mov di,offset sbox
        inc si
        
        loop looop1
        ret
     endp
     
     
        
        
          
          
          
          
          
          
          
          
          
          
      
      
    proc Arrange_Array
            xor ax,ax
            xor dx,dx
            xor si,si
            xor di,di
            xor cx,cx
            xor bx,bx 
         mov si,offset true_message
         mov di, offset Arranged_Message
        mov cx,4
        l5:
        mov al,[si]
        mov [di],al
        inc si
        add di,4 
        loop l5
        
        
        mov cx,4
        mov di,offset Arranged_Message+1
        l6:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop l6
        
        mov cx,4
        mov di, offset Arranged_Message+2
        l7:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop l7
        
        mov cx,4
        mov di,offset Arranged_Message+3
        l8:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop l8
        ret
     endp
        
          
         
         
         
         
         
         
         
         
         
         
       
    proc Shift_Rows
            xor ax,ax
            xor dx,dx
            xor si,si
            xor di,di
            xor cx,cx
            xor bx,bx  
            
       mov bx, offset Arranged_Message
       add bx, 4 
       mov al, [bx]
       mov cx,3
       mov si,offset Arranged_Message
       l1:
       mov bl, [si+5] 
       mov [si+4],bl
       inc si
       loop l1
       mov si,offset Arranged_Message
       mov [si+7],al
       
       
       mov al,[si+8]
       mov bl,[si+9] 
       mov cx,2
       l2:
       mov dl,[si+10]
       mov [si+8],dl 
       inc si
       loop l2
       mov si,offset Arranged_Message
       mov [si+10],al
       mov [si+11],bl 
       
       mov cx,3
       mov dl,[si+15]
       l3:
       mov al,[si+14]
       mov [si+15],al
       dec si
       loop l3
       mov si,offset Arranged_Message
       mov [si+12],dl
       
       ret
    endp
    
    
    
    
    
    
    
    
    
    
    
    
    proc Add_Round_Key
         xor ax,ax
        xor bx,bx
        xor cx,cx
        xor dx,dx
        xor si,si
        xor di,di
        xor bp,bp
         mov si, offset Arranged_Message
         mov di, offset Arranged_Key      ;instructions: si holds "true_message" offset and di holds "key_message" offset.  
         xor ax,ax   
         mov cx,16         ;cx holds the number of loops-16(xor for each letter in a string of 16 letters)
         looper:
         mov al,[si]       ;saving the values of the first letter of the strings
         mov bl,[di]
         xor al,bl         ;xoring the toe letters that are in al and ah
         mov [si], al
         inc si            ;increasing the offsets each loop in order to go over the whole string's letters
         inc di
         loop looper
         ret                ;looping our labled code 16 times(cx)
     endp
     
        
       
       
       
       
       
       
       
    proc input_string 
            xor ax,ax
            xor dx,dx
            xor si,si
            xor di,di
            xor cx,cx
            xor bx,bx
        mov dx,offset temp_message
        mov ah,0ah
        int 21h
        mov di,offset temp_message+2
        mov si,offset true_message
        mov cx,16 
        ins:
        mov al,[di]
        mov [si],al
        inc si
        inc di
        loop ins
        ret
    endp                 
       
       
       
       
       
    
    proc input_key
        xor ax,ax
        xor bx,bx
        xor cx,cx
        xor dx,dx
        xor si,si
        xor di,di
        mov dx,offset temp_key
        mov ah,0ah
        int 21h 
        
        mov cx,16
        mov si,offset true_key 
        mov di,offset temp_key 
        add di,2
        lop:
        mov al,[di]
        mov [si],al
        inc si
        inc di
        loop lop 
        mov si,offset true_key
        mov [si+16],'$'
        ret
     endp
         
         
          
          
          
          
          
          
          
        proc shl_every_round_for_rcon
             xor ax,ax
        ;xor bx,bx
        xor cx,cx
        xor dx,dx
        xor si,si
        xor di,di
        ;xor bp,bp
             mov si,offset rcon
             mov cx,10
             shiftl:
             mov al,[si+1]
             mov [si],al
             inc si
             loop shiftl
             ret
        endp
            
            
            
            
            
            
            
            
             
             
        proc Print_Out_CipherText
            mov si,offset Arranged_Message
            mov di,offset final
            mov cx,4
            colo1:
            mov al,[si]
            mov [di],al
            add si,4 
            inc di
            loop colo1
            mov si,offset Arranged_Message+1
            mov cx,4
            colo2:
            mov al,[si]
            mov [di],al
            add si,4
            inc di
            loop colo2
            mov si,offset Arranged_Message+2
            mov cx,4
            colo3:
            mov al,[si]
            mov [di],al
            inc di
            add si,4
            loop colo3
            
            mov si,offset Arranged_Message+3
            mov cx,4
            colo4:
            mov al,[si]
            mov [di],al
            inc di
            add si,4
            loop colo4
            mov di,offset final
            mov [di+16],'$'
            mov ah,09
            mov dx,offset final
            int 21h
            
            ret
        endp
        
        
            
            
            
            
            
            
        
          
          
          
          
          
       
             
             
             
             
;///////////////////////////////////////////////////////////////////////////////////////////////////////////////             
;///////////////////////////----decryption process----//////////////////////////////////////////////////////////
;/////////////////////////////////////////////////////////////////////////////////////////////////////////////// 
    
    
    
    
    
    
    proc input_cipherkey
        xor ax,ax
        xor bx,bx
        xor cx,cx
        xor dx,dx
        xor si,si
        xor di,di
        mov dx,offset temp_cipherkey
        mov ah,0ah
        int 21h 
        
        mov cx,16
        mov si,offset cipherkey 
        mov di,offset temp_cipherkey 
        add di,2
        lop1:
        mov al,[di]
        mov [si],al
        inc si
        inc di
        loop lop1
        ret
    endp
    
    
        
        
        
        
          proc input_ciphertext 
            xor ax,ax
            xor dx,dx
            xor si,si
            xor di,di
            xor cx,cx
            xor bx,bx
        mov dx,offset temp_ciphertext
        mov ah,0ah
        int 21h
        mov di,offset temp_ciphertext+2
        mov si,offset ciphertext
        mov cx,16 
        ins1:
        mov al,[di]
        mov [si],al
        inc si
        inc di
        loop ins1
        ret
    endp                 
       
        
        










   proc Arrange_Array_cipherkey
            xor ax,ax
            xor dx,dx
            xor si,si
            xor di,di
            xor cx,cx
            xor bx,bx 
         mov si,offset cipherkey
         mov di, offset Arranged_cipherkey
        mov cx,4
        a11:
        mov al,[si]
        mov [di],al
        inc si
        add di,4 
        loop a11
        
        
        mov cx,4
        mov di,offset Arranged_cipherkey+1
        a21:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop a21
        
        mov cx,4
        mov di, offset Arranged_cipherkey+2
        a31:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop a31
        
        mov cx,4
        mov di,offset Arranged_cipherkey+3
        a41:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop a41
        ret
   endp
   
               
               
               
               
               
               
               
                
  proc Arrange_Array_ciphertext
            xor ax,ax
            xor dx,dx
            xor si,si
            xor di,di
            xor cx,cx
            xor bx,bx 
         mov si,offset ciphertext
         mov di, offset Arranged_ciphertext
        mov cx,4
        a1:
        mov al,[si]
        mov [di],al
        inc si
        add di,4 
        loop a1
        
        
        mov cx,4
        mov di,offset Arranged_ciphertext+1
        a2:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop a2
        
        mov cx,4
        mov di, offset Arranged_ciphertext+2
        a3:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop a3
        
        mov cx,4
        mov di,offset Arranged_ciphertext+3
        a4:
        mov al,[si]
        mov [di],al
        inc si
        add di,4
        loop a4
        ret
     endp  
               
               
                   
                   
                   
                   
               
               
               
               
            proc Inverse_Byte_Substitution 
                push dx
                push si
                xor ax,ax
                ;xor dx,dx
                xor si,si
                xor di,di
                xor cx,cx
                MOV CX,16
                  mov si,offset Arranged_ciphertext
                 mov di, offset inverse_sbox
                 mov cx,16 
                     looop12:
                 mov al,[si]
                 add di,ax
                 mov bl,[di]
                 mov [si],bl
                 mov di,offset inverse_sbox
                 inc si
                 loop looop12
                 pop dx
                 pop si
                    ret
               endp 
            
                    
                    
                    
                    
                    
              
              
              
            proc Inverse_Shift_Rows
                push dx 
                push si
                xor ax,ax
                ;xor dx,dx
                xor si,si
                xor di,di
                xor cx,cx
                xor bx,bx 
                mov si,offset Arranged_ciphertext
                mov al,[si+7]
                mov cx,3
                row1:
                mov bl,[si+6]
                mov [si+7],bl
                dec si
                loop row1
                mov si,offset Arranged_Ciphertext
                mov [si+4],al
                
                mov dl,[si+10]
                mov bl,[si+11] 
                mov cx,2
                row2:
                mov al,[si+8]
                mov [si+10],al
                inc si
                loop row2
                
                mov si,offset Arranged_ciphertext 
                mov [si+8],dl
                mov [si+9],bl
                
                mov cx,3
                mov dl,[si+12]
                row3:
                mov al,[si+13]
                mov [si+12],al
                inc si
                loop row3 
                mov si,offset Arranged_ciphertext
                mov [si+15],dl
                pop dx
                pop si
                ret
            endp
             
             
             
             
             
                  
                  
                  
                  
                  
                  
             
;//inverse mixcol/////////////////////////////////////////////////////////////////////////////////////////             
            proc mul9
                 xor ax,ax 
                 push di
                 mov al,[si]
                 mov di,offset multiply_9
                 add di,ax
                 mov ax,[di]
                  pop di
                 ret
            endp 
            
               
               
               
               
               
               
            proc mul11 
                xor AX,AX
                push di
                mov al,[si]
                mov di,offset multiply_11
                add di,ax
                mov ax,[di]
                pop di
                ret
            endp
              
              
              
              
              
              
              
              
              
            proc mul13
                xor ax,ax 
                push di
                mov al,[si]
                mov di,offset multiply_13
                add di,ax
                mov ax,[di]
                pop di
                ret
            endp
             
             
            proc mul14
                xor ax,ax
                push di
                mov al,[si]
                mov di,offset multiply_14
                add di,ax
                mov ax,[di]
                pop di
                ret
            endp
            
            
                
                
                
                
   proc Multiplytempcol_once_inverse
        
        cmp [di],9
        jz x1
        cmp [di],11
        jz y1
        cmp [di],13
        jz z1 
        cmp [di],14
        jz xy1
        
        x1:
        call mul9
        jmp eny
        y1:
        call mul11
        jmp eny
        z1:
        call mul13
        jmp eny1
        xy1:
        call mul14
        jmp eny1
        eny1:
        
        ret
   endp
   
          
          
          
          
          
          
          
          
          
    proc multiplyall_inverse 
        
        mov si, offset inverse_tempcol
        mov cx,4
        all1:
        call multiplytempcol_once_inverse
        mov [si],al
        inc si
        inc di
        loop all1 
        ret
    endp 
       
       
       
       
       
       
       
       
    proc xortempcol_inverse        
        
        mov si,offset inverse_tempcol 
        mov ax, [si]
        mov cx,3
        jj1: 
        xor ax,[si+1]
        inc si
        loop jj1
        ret 
        
        ;returns the value in al
    endp
   
   
   
   
           
            
            
            
            
            
            
            
            
         
         
         
         
         
            
     proc inserttotempinverse1
         push di
                                            
        mov di, offset Arranged_Ciphertext+1
        mov si,offset inverse_tempcol 
        mov cx,4
        run21:
        mov al,[di]
        mov [si],al 
        add di,4
        inc si
        loop run21
        pop di
        
        
        ret
     endp
       
         
         
         
         
         
         
       
     proc inserttotempinverse2
         push di
                                            
        mov di, offset Arranged_Ciphertext+2
        mov si,offset inverse_tempcol 
        mov cx,4
        run11:
        mov al,[di]
        mov [si],al 
        add di,4
        inc si
        loop run11
        pop di
        
        
        ret
      endp
          
          
          
          
          
          
          
          
          
          
          
          
          
       proc inserttotempinverse3
         push di                                  
        mov di, offset Arranged_Ciphertext+3
        mov si,offset inverse_tempcol 
        mov cx,4
        run31:
        mov al,[di]
        mov [si],al 
        add di,4
        inc si
        loop run31
        pop di
        ret
       endp
          
          
         
         
         
         
         
         
          
    proc inserttotempinverse
         push di                                 
        mov di, offset Arranged_Ciphertext
        mov si,offset inverse_tempcol 
        mov cx,4
        run12:
        mov al,[di]
        mov [si],al 
        add di,4
        inc si
        loop run12
        pop di
        ret
    endp
    
    
    
      
      
      
      
      
      
      
   proc mixcol1_inverse 
     mov bp,4
     
     mov bx,offset afterinversemix
     ;mov cx,4
     
     firstcol1: 
     call inserttotempinverse
     call multiplyall_inverse
     call xortempcol_inverse 
     mov [bx],al 
     add bx,4
     cmp bp,0
     dec bp
     jnz firstcol1          
     ret
   endp 
     
     
      
      
      
      
      
      
      
      
      
      
   proc mixcol2_inverse
     mov bp,4 
     mov bx, offset afterinversemix+1
     seconedcol1:
     call inserttotempinverse1
     call multiplyall_inverse
     ;mov di,offset multiply
     call xortempcol_inverse
     mov [bx],al
     add bx,4
     cmp bp,0
     dec bp
     jnz seconedcol1
     ret
   endp
       
       
       
       
       
       
       
       
       
       
   proc mixcol3_inverse
     mov bp,4 
     mov bx, offset afterinversemix+2
     thirdcolumn1:
     call inserttotempinverse2
     call multiplyall_inverse
     ;mov di,offset multiply
     call xortempcol_inverse
     mov [bx],al
     add bx,4
     cmp bp,0
     dec bp
     jnz thirdcolumn1
     ret
   endp  
   
    
    
    
    
    
    
    
    
   
  proc mixcol4_inverse
        
     mov bp,4 
     mov bx, offset afterinversemix+3
     fourthcolumn1:
     call inserttotempinverse3
     call multiplyall_inverse
     ;mov di,offset multiply
     call xortempcol_inverse
     mov [bx],al
     add bx,4
     cmp bp,0
     dec bp
     jnz fourthcolumn1
     ret
  endp
  
  
       
       
       
       
       
       
       
       
       
       
       
       
  
  proc CopyAfterMix_ColumnsTotArranged_Message_inverse
        mov si,offset afterinversemix
        mov di,offset Arranged_ciphertext
        mov cx,16
        copy113:
        mov al,[si]
        mov [di],al
        inc si
        inc di
        loop copy113
        ret
    endp
    
    
        
        
        
        
        
    proc Inverse_Mix_Columns
        
        push si
         xor ax,ax
        xor bx,bx
        xor cx,cx
        ;xor dx,dx
        xor si,si
        xor di,di
         mov di,offset inverse_multiply
         call mixcol1_inverse 
     
         mov di,offset inverse_multiply
         call mixcol2_inverse 
     
         mov di,offset inverse_multiply
         call mixcol3_inverse 
     
        mov di,offset inverse_multiply
        call mixcol4_inverse
        
        call CopyAfterMix_ColumnsTotArranged_Message_inverse
          
        pop si
        ret
    endp
    
    
       
       
       
       
       
    proc Inverse_Add_RoundKey 
        push dx
        push si
        mov si,offset Arranged_ciphertext
        mov di,offset Arranged_Cipherkey
        mov cx,16
        addr:
        mov al,[si]
        mov bl,[di]
        xor al,bl
        mov [si],al
        inc si
        inc di 
        loop addr
        pop si
        pop dx
        ret
    endp
    
            
            
            
            
    
    
    
    
    
     proc Inverse_Keys_Expansion
            push dx
            push si  
            xor ax,ax
            xor dx,dx
            xor si,si
            xor di,di
            xor cx,cx
            ;xor bx,bx 
            mov di, offset Arranged_Cipherkey+3
            mov si, offset temp
            mov cx,4
            
            insert1:
            mov dl,[di]
            mov [si],dl
            add di, 4
            inc si
            loop insert1
            
            mov cx,3
            mov si, offset temp
            mov dl,[si]
            shift1:
            mov al,[si+1]
            mov [si],al 
            inc si
            loop shift1
            mov si, offset temp
            mov [si+3],dl
;           
            mov si,offset temp
            mov di, offset sbox
            mov cx,4 
            looop11:
            mov al,[si]
            add di,ax
            mov dl,[di]
            mov [si],dl
            mov di,offset sbox
            inc si
            loop looop11
;           rcon
            mov di ,offset rcon
            mov si,offset temp 
            mov aL,[si]
            xor al,[di]
            mov [si],al
            
            
             
             
             
            ;xor with first
            mov di, offset Arranged_Cipherkey
            mov si, offset temp 
            mov cx,4
            col11:
            mov al ,[di]
            mov dl, [si]
            xor al,dl
            mov [di],al
            mov [si],al
            add di,4
            inc si
            loop col11 
            
            ;now temp holds first new col 
             
             
             ;xorscond
             mov di,offset Arranged_Cipherkey+1
             mov si,offset temp
             mov cx,4
             col21:
             mov al,[di]
             mov dl,[si]
             xor al,dl
             mov [di],al
             mov [si],al
             inc si
             add di,4
             loop col21
             ;xorthird
             mov di,offset Arranged_Cipherkey+2
             mov si,offset temp
             mov cx,4
             col31:
             mov al,[di]
             mov dl,[si]
             xor al,dl
             mov [di],al
             mov [si],al
             inc si
             add di,4
             loop col31
             ;xorfourth
             mov di,offset Arranged_cipherkey+3
             mov si,offset temp
             mov cx,4
             col41:
             mov al,[di]
             mov dl,[si]
             xor al,dl
             mov [di],al
             mov [si],al
             inc si
             add di,4
             loop col41
             
             
             mov cx,16
             mov di,offset Arranged_cipherkey 
             copy_to_allroundkeys:
             mov al,[di]
             mov [bx],al
             inc di
             inc bx
             loop copy_to_allroundkeys
             pop si
             pop dx
             ret
         endp
          
              
              
              
              
              
              
              
          proc All_Round_Inversed_Key
            mov bp,10
            mov bx,offset allroundkeys
            insertall1:
            call Inverse_Keys_Expansion
            call shl_every_round_for_rcon
            dec bp
            cmp bp,0
            jnz insertall1
            ret
          endp  
             
             
             
             
             
             
             
          
        proc Update_Cipherkey 
             push dx
             
             mov di,offset Arranged_CipherKey
             mov cx,16
             update:
             mov al,[si]
             mov [di],al
             inc si
             inc di
             loop update
             sub si,32
             pop dx 
             
                         
             ret  
        endp
        
             
             
             
             
             
             
             
        proc copkey 
            mov si,offset copy1
            mov di,offset Arranged_cipherkey
            mov cx,16
            lj:
            mov al,[di]
            mov [si],al 
            inc si
            inc di
            loop lj
            ret
        endp  
        
        
        
        
        
        
        
        
        proc lastrndkey
            mov si,offset Arranged_Ciphertext
            mov di ,offset copy1 
            mov cx,16
            ls:
            mov al,[si]
            mov bl,[di]
            xor al,bl
            mov [si],al 
            inc si
            inc di
            loop ls
            ret
        endp
        
                 
                 
                 
                 
                 
                 
        
        proc ciphertext_to_final
            mov si,offset final
            mov di ,offset Arranged_Ciphertext
            mov cx,4
            kh:
            mov al,[di] 
            mov [si],al
            inc si
            add di,4
            loop kh
            
            mov cx,4
            mov di,offset Arranged_ciphertext+1
            
            gh:
            mov al,[di]
            mov [si],al
            inc si
            add di,4
            loop gh
            
            mov cx,4
            mov di,offset Arranged_ciphertext+2
           
            fg:
            mov al,[di]
            mov [si],al
            inc si
            add di,4
            loop fg
            
            mov cx,4
            mov di,offset Arranged_Ciphertext+3 
            dsa:
            mov al,[di]
            mov [si],al
            inc si
            add di,4
            loop dsa 
            mov [si+1],'$'
            ret
        endp 
            
            
                
                
                
                
                
                
                
                
                
                
            proc Print_Final_In_Hex
            mov si,offset final
            mov bx,offset Last_hex
            mov cx,16
            prin:
            
            mov di,offset hex
            xor ah,ah 
            mov al,[si]
            shr al,4
            add di,ax 
            mov dl,[di]
            mov [bx],dl
            inc bx
            mov di,offset hex
            mov al,[si]
            and al,0fh
            add di,ax 
            mov dl,[di]
            mov [bx ],dl
            inc bx
            mov [bx],'H'
            inc bx
            mov [bx]," " 
            INC BX
            inc si
            loop prin 
            MOV [BX],'$' 
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h 
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            mov dx,offset outp
            mov ah,09h
            int 21h
            
            mov dx,offset Last_hex
            mov ah,9h
            int 21h
            ret
         endp
         
         
         
         
         
         
         
        
        
        
        
;///////file encryption procs////////////////////////////////////////////////////////////
proc File_Encryption_Guide
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            mov dx,offset intro1
            mov ah,09
            int 21h
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            mov dx,offset intro2
            mov ah,09
            int 21h      
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
             mov dx,offset intro22
            mov ah,09
            int 21h      
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            mov dx,offset intro3
            mov ah,09
            int 21h      
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            
            mov dx,offset intro33
            mov ah,09
            int 21h 
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            mov dx,offset intro332
            mov ah,09
            int 21h 
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
           
            
            mov dx,offset intro34
            mov ah,09
            int 21h 
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            
            mov dx,offset intro4
            mov ah,09
            int 21h 
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            
            
            
            
            mov dx,offset intro5
            mov ah,09
            int 21h 
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            ret
endp






proc input_file_name
    mov ah,0ah
    mov dx,offset temp_name
    int 21h
    
    mov cx,7
    mov si,offset temp_name+2
    mov di,offset file_name
    looped:
    mov al,[si]
    mov [di],al
    inc si
    inc di
    loop looped
    ret
endp 
         
         
         
         
         
         
         
         
      proc Read_16b
        mov si,offset file_handle
        
        mov bx,[si]
        mov al,2
        mov ah,3fh
        mov cx,16
        
        mov dx,offset file_data
        int 21h
        ret
      endp 
      
         
         
         
         
         
         
         
      proc Copy_To
        mov si,offset true_message
        mov di,offset file_data
        mov cx,16
        lkop:
        mov al,[di]
        mov [si],al
        inc si
        inc di
        loop lkop
        ret
      endp
      
      
      
      
      
      
      
        
        
        
        
   proc Encrypt_16b
       call Read_16b
        call copy_to
        
        call Arrange_Array
             ;first round
            call Add_Round_Key 
            call Keys_Expansion
            call Byte_Substitution
            call Shift_Rows 
            call Mix_Columns
            call Add_Round_Key 
     
                ;middle rounds
                mov dx,8
                push dx 
                 rounding:
                call clear_all_registers
                call shl_every_round_for_rcon
                call Keys_Expansion
                call Byte_Substitution                   
                call Shift_Rows
                call Mix_Columns
                call Add_Round_Key
                pop dx
                dec dx
                push dx
                cmp dx,0
                jnz rounding
                pop dx
                ;final last round, the 10th round, withount Mix_Columns
                call shl_every_round_for_rcon
                call Keys_Expansion
                call Byte_Substitution
                call Shift_Rows
                call Add_Round_Key 
                call Write_16b
                
                ret
   endp
   
          
          
          
          
          
          
          
          
          
   
   proc Write_16b
    
                xor ax,ax 
                mov si,offset new_file_handle
                mov bx,[si]
                 mov ah,40h
                 mov cx,16
                 mov dx,offset Arranged_message 
                 int 21h 
                 ret
   endp
   
   
   
   
   
           
         
         
         
           
       proc calc_file_size;/getting number of loops to preform
            xor ax,ax 
            xor cx,cx
            xor dx, dx
            mov si,offset File_Handle 
            mov bx,[si]
            mov al,2
            mov ah,42h
            int 21h
            ;/size in al
            mov bl,16
            div bl
            mov si,offset rounds
            mov [si],al
            
            mov al,0
            mov ah,42h
            mov si,offset File_Handle
            mov bx,[si]
            int 21h
            
            
            ret
       endp
       
       
            
            
            
            
           
            
             
        
   
   
                
               
      proc Keep_Key_Safe_copy
        mov si,offset Arranged_Key
        mov di,offset safe_key
        mov cx,16
        lops:
        mov al,[si]
        mov [di],al
        inc si
        inc di
        loop lops
        ret
      endp 
      
      
      
      proc Create_new_file
         mov dx,offset new_file
         mov cx,6
         mov ah,3ch
         int 21h
         ret
      endp
      
      
         
         
      
      
           
           
           
           
           
           
           
      proc ReCreate_Original_Key
          mov si,offset safe_key
          mov di,offset Arranged_key
          mov cx,16
          recreate:
          mov al,[si]
          mov [di],al
          inc si
          inc di
          loop recreate
          ret
      endp
      
      
      
      
        
        
        
        
        

        
        
        
        
        
     
        
        
            
        
        
        
        
          
              
              
              
              
          
;////////////////////////////////////////////////-main options procs-//////////////////////////          
          
          
                               
                               
                               
                               
                               
                               
                               
                               
          
         proc Encrypt_128_bits_Block_In_Plain_Text
            ;inputing key and arranging it 
            mov dx,offset kp
            mov ah,09
            int 21h
            
            call input_key
            call Arrange_Array_Key
            ;inputing text and arranging it
            ;push dx
             MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h 
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            mov dx,offset mp
            mov ah,09
            int 21h
            call input_string 
            call Arrange_Array
             ;first round
            call Add_Round_Key 
            call Keys_Expansion
            call Byte_Substitution
            call Shift_Rows 
            call Mix_Columns
            call Add_Round_Key 
     
                ;middle rounds
                mov dx,8
                push dx 
                 rounding11:
                call clear_all_registers
                call shl_every_round_for_rcon
                call Keys_Expansion
                call Byte_Substitution                   
                call Shift_Rows
                call Mix_Columns
                call Add_Round_Key
                pop dx
                dec dx
                push dx
                cmp dx,0
                jnz rounding11
                ;final last round, the 10th round, withount Mix_Columns
                call shl_every_round_for_rcon
                call Keys_Expansion
                call Byte_Substitution
                call Shift_Rows
                call Add_Round_Key
                 MOV dl, 10
                MOV ah, 02h
                INT 21h
                MOV dl, 13
                MOV ah, 02h
                INT 21h
                call Print_Out_CipherText
                
                call Print_Final_In_Hex  
                RET
         endp
         
          
          
          
          
          
          
          
         
         
         
          
        proc Decrypt_128_bits_Block_in_Plain_Text 
                MOV DX,OFFSET XP
                MOV AH,9H
                INT 21H
                
                call input_ciphertext
                call Arrange_Array_Ciphertext
                 mov dx,offset cp
                 mov ah,09
                 int  21h
                 call input_cipherkey
                 call Arrange_Array_cipherkey
                 call copkey
                call All_round_inversed_key
                mov si,offset allroundkeys+144
   
     
     
                ;first decryption round
                 call Update_Cipherkey 
                call inverse_Add_roundkey 
                 call inverse_shift_rows
                    call inverse_Byte_Substitution 
                ;9 middle rounds
                 mov dx,9
                  hlo:
                     call Update_Cipherkey
                call inverse_add_roundkey  
                call inverse_mix_columns
                call inverse_shift_rows
                 call inverse_byte_substitution
                dec dx 
                cmp dx,0
                 jnz hlo
                 ;xor with rhe first inputed key we copied at first
                 call lastrndkey  
                 call ciphertext_to_final
                 mov dx,offset final
                 mov ah,09 
                 int 21h
                 call Print_Final_In_Hex
                 ret
        endp
        
        
        
        
        
        
        
        
        
    proc Encrypt_File_using_aes_128b;//////
        call Create_new_file
        call File_Encryption_Guide
        call input_file_name
        mov al,0
        mov dx,offset file_name
        mov ah,3dh
        int 21h 
        mov si,offset file_handle
        mov [si],ax
        
           mov al,2
           mov ah,3dh
           mov dx,offset new_file
           int 21h
           mov si,offset new_file_handle
           mov [si],ax
           
            mov dx,offset kp
            mov ah,09
            int 21h
                  
            call input_key
            call Arrange_Array_Key
            call keep_key_safe_copy
            call calc_file_size
            ;//inner loop
            
            xor ah,ah
            mov al, rounds
            push ax
            rounding12:
            
            call Encrypt_16b
            call Write_16b
            call ReCreate_Original_Key
            pop ax
            dec ax 
            push ax
            cmp al,0
            jnz rounding12
            pop ax
           
      
           mov ah,3eh
           mov si,offset new_file_handle
           mov bx,[si]
           int 21h 
           
           mov dx,offset dune
           mov ah,09h
           int 21h
           ret
    endp 
    
    
    
    
    
    ;;;;////////////////final proc 'menu'///////////////////////////////////////////////////////
    ;//////////////////////////////////////////////////////////////////////////////////////////
    ;/////////////////

;finally all the code up comes down to this menu proc!!
    
    
    ;this is the last proc on the program and the only one to be called on the 'main'. 

;this proc will let the user pick an option for the main procs using keyboard shortcuts

;the main 3 procs can be found just above this title

;the options are: decryption,encryption and file encryption 

;this is the only proc to be called in the main and it will manage the whole program 

        proc menu
             mov dx,offset pick
            mov ah,09
            int 21h
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
             mov dx,offset left
            mov ah,09
            int 21h
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            
             mov dx,offset right
            mov ah,09
            int 21h
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            
            
            mov dx,offset up
            mov ah,09
            int 21h
            
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            
            
            
            INT 21h
            MOV dl, 10
            MOV ah, 02h
            
            
            
            
            
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
            MOV dl, 10
            MOV ah, 02h
            INT 21h
            MOV dl, 13
            MOV ah, 02h
            INT 21h
             
             
             
             
            mov ah,08h
            int 21h
            
            cmp al,66h
            jz file_encryption
            cmp al,65h
            jz encryption
            cmp al,64h
            jz decryption 
             
            
            
            
            
             decryption:
              call Decrypt_128_bits_Block_in_Plain_Text
              jmp endingall
             encryption:
             
             call Encrypt_128_bits_Block_In_Plain_Text 
             jmp endingall
             file_encryption:
             
             call Encrypt_File_using_aes_128b
             jmp endingall
             
             endingall:
             nop
             ret
        endp
        
        
           
          
       
       
       
       
            
            
          
;//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////  
    start: 


;set segment registers:
    mov ax, data
    mov ds, ax  
              ;THIS PROC IS RESPONSIBLE FOR THE WHOLE CODE
            call menu 
                 
                 
                 
                 
                 
                 
            ;//trusted url to check the output of the encrypyon===>>>        http://aes.online-domain-tools.com/ 
 
end start ; set entry point and stop the assembler.
  