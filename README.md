# IPK Projekt 2: Klient pre chat server používajúci IPK24-CHAT protokol

## Obsah
- [Úvod](#úvod)
- [Architektúra aplikácie](#architektúra-aplikácie)
  - [UML diagram](#uml-diagramy)
- [Testovanie](#testovanie)
  - [Testovacie prostredie](#testovacie-prostredie)
  - [Testovacie prípady](#testovacie-prípady)
- [Extra funkcionality](#extra-funkcionality)
- [Bibliografia](#bibliografia)

## Úvod
Účelom tejto dokumentácie je poskytnúť podrobný popis funkčnosti a implementácie paketového čmuchaču. Čmuchač je nástroj používaný na zachytávanie sieťových paketov, ktoré prechádzajú cez sieťové rozhranie, na ktorom práve čuchá. Po nastavení príslušných filtrov program "čuchá" (zachytáva) pakety podľa definovaných kritérií.

Pri zachytávaní paketov je kľúčové správne rozpoznať typ paketu, či už ide o IPv4, IPv6, alebo ARP, na čo sú vytvorené špecifické metódy. Každý z týchto typov má svoje vlastnosti a metódy, ktoré umožňujú analyzovať a vypísať informácie daného paketu.

## Architektúra aplikácie

### Filter modul `filter.cpp`
* Tento modul obsahuje metódy `createFilter` , `parseArgs` , `PrintAllActiveInterfaces` a `signalHandler` , ktoré zabezpečujú spracovávanie vstupných argumentov a následnú generáciu filteru, ktorý je neskôr nastavený pre zachytávanie.
### Main modul
* Tento modul zahŕňa hlavnú funkciu programu, ktorá inicializuje konfiguračnú štruktúru `Config` a vyvolá statické metódy z triedy `filter`.
* Následne inicializuje inštanciu triedy `sniffer` a volá jej príslušné metódy pre správne zachytávanie paketov.
### Sniffer modul
* Tento modul vykonáva požadovanú funkcionalitu čuchaču, tj. vypisovanie informácií o jednotlivých paketoch.
* Obsahuje definíciu triedy `Sniffer`, ktorá obsahuje metódy `Sniffer()`, `setFilter` , `handleIPv4Packet`, `handleIPv6Packet`, `handleArpPacket` , `printTcpPacket`, `printUdpPacket`, `printIcmpPacket` , `printPacket`, `printPacketData`.
* Tieto metódy slúžia pre štart zachytávania paketov na danom rozhraní, pre nastavenie filteru a pre následné vetvové spracovávanie paketov podľa ich typu v metóde `printPacket`.
* Pre každý typ paketu existuje metóda, kde sa vypisujú jej unikátne a užitočné informácie.
* Ako posledné sa vypíše hexa a ascii reprezentácia obsahu paketu. Tento výpis je inšpirovaný výpisom z nastároju Wireshark.
### UML diagram
[UML diagram](uml.png)

## Testovanie
Testovanie bolo vykonané pomocou rôznych "ping" príkazov a iných nástrojov na generovanie sieťovej premávky, čo nám umožnilo ověřit funkčnosť na rôznych sieťových protokoloch a paketoch. Čmuchač paketov bol schopný detekovať a analyzovať všetky typy paketov podľa zadania.
Testy zahrňovali presné výpisy podobné nástroju Wireshark pre zobrazenie informácií o paketoch.
### IPv4
* Igmp - `tcpreplay -t -i lo IGMP_V1.cap`
### IPv6
* Icmp6 - `python skript`
* ndp - `ping6 fe80::1%eth0`
* mld - `python skript`
### Arp
* arp - `arping -I eth0 192.168.1.1`


## Bibliografia
* C++ referencia[online]: https://en.cppreference.com/w/ cited [2024-04-10]
* Wikipedia, the free encyclopedia[online]: http://en.wikipedia.org/wiki/Pcap cited [2024-04-15] 
* ChatGPT[online]: https://chat.openai.com/ cited [2024-04-20]
* [RFC2236] Fenner, W.  Internet Group Management Protocol, Version 2 [online]. November 1997. [cited 2024-04-20]. Available at: https://datatracker.ietf.org/doc/html/rfc2236
* [RFC2236] Conta, A. Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification, Version 2 [online]. March 2006. [cited 2024-04-20].Available at: https://datatracker.ietf.org/doc/html/rfc4443
* [RFC2236] C. Plummer, David.  An Ethernet Address Resolution Protocol [online]. November 1982. [cited 2024-04-20]. Available at: https://datatracker.ietf.org/doc/html/rfc826
* [RFC2236] Deering, S. Internet Protocol, Version 6 (IPv6) Specification [online]. December 1998. [cited 2024-04-20]. Available at: https://datatracker.ietf.org/doc/html/rfc2460


