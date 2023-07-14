### O scurta descriere a implementarii: ###

In cadrul functiei `check_and_solve_packet()` verifica ce tip de pachet
s-a primit si se actioneaza corespunzator acestuia.

Mai intai, se verifica daca pachetul este de tip ARP prin intermediul
identificatorului de protocol incapsulat (`ether_type`).

Daca ARP opcode este: 
- request (1): se trimite un ARP reply cu adresa mac a interfetei pe care
                s-a primit pachetul si se adauga senderul in tabela routerului,
                daca nu este deja.
- reply (2): se adauga noua adresa mac (cu ip) in tabela ARP a routerului.

Daca nu este un pachet ARP se verifica daca routerul este destinatarul pachetului,
caz in care este un pachet ICMP `"Echo request"`.
Acest lucru este realizat prin verificarea adreselor ethernet, IPv4, daca
protocolul IP este de tip ICMP, tipul ICMP este 8 si codul 0. Astfel, se 
asigura faptul ca routerul este destinatarul si trimite un `"Echo reply"`.
Procesul de realizare a unui pachet ICMP v-a fi dezvoltat mai tarziu.

Daca pachetul nu este unul ARP sau o cerere ICMP, atunci inseamna ca este de
tip IPv4, evident acest lucru este verificat prin indentificatoul ethernet.
In acest caz sunt urmatii pasii:
- se verifica checksum

- se verifica si actualizeaza TTL:
    - daca ttl <= 1, pachetul trebuie aruncat si se trimite un mesaj 
    ICMP `Time exceeded` (type 11, code 0)

- se cauta in tabla de rutare urmatoarea destinatie a pachetului:
    - cautarea se realizaza utilizand cautare binara pentru indicele de tabela
        (sortata pe baza prefixelor si mastilor), in momentul in care se gaseste
        prefixul bun, se cauta cea mai mare masca posibila pentru acel prefix
    - daca nu se gaseste indicele corespunzaotr in tablea de rutare, atunci
    pachetul trebuie aruncat si se trimite un mesaj ICMP `Destination unreachable`
    (type 3, code 0) 

- se cauta in tablea ARP adresa mac a interfetei si urmatoarei destinatii
    pe care trebuie trimis pachetul:
    - daca nu se gaseste adresa urmatoarei destinatii, atunci inseamna ca trebuie 
    sa punem pachetul in coada (se reseteaza ttl si checksum ul vechi)
    - se trimite o cerere ARP pe interfata (in mod normal trebuia trimisa broadcast,
    dar in acest caz cunoastem unde ar trebui sa trimitem mesajul pe interfata)

- se seteaza sursa si destinata in headerul ehternet

- se calculeaza noul checksum IPv4

- se trimite mesajul

    Pentru realizarea mesajului ICMP, se realizeaza un pachet in care se preiau datele
necesare din pachetul vechi (adresele sau alte date care trebuie trimise).
- Pentru ICMP tip 8, se seteaza ICMP id si sequence ca cele din pachetul vechi si
se copiaza datele de dupa ICMP. Pe scurt se pastreaza trimit aceleasi date ca
in pachetul vechi, dar se schimba adresele.
- Pentru ICMP tip 3 sau 11, se seteaza id si sequence cu 0 si dupa ICMP se copiaza 
headerul IPv4 vechi si primii 64 de biți din payload-ul pachetului original.
    Aceste mesaje se trimit pe aceasi interfata pe care s-au primit.


