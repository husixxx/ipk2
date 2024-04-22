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
* Obsahuje definíciu triedy `Sniffer`, ktorá obsahuje metódy `Sniffer()`, `setFilter` , `handleIPv4Packet`, `handleIPv6Packet`, `handleArpPacket` , `printTcpPacket`, `printUdpPacket`, `printIcmpPacket`.
* Tieto metódy slúžia pre štart zachytávania paketov na danom rozhraní, pre nastavenie filteru a pre následné vetvové spracovávanie paketov podľa ich typu.
* Pre každý typ paketu existuje metóda, kde sa vypisujú jej unikátne a užitočné informácie.

## Testovanie
### IPv4
* Igmp - `tcpreplay -t -i lo IGMP_V1.cap`
### IPv6
* Icmp6
** ndp - `ping6 fe80::1%eth0`
** mld
### Arp
`arping -I eth0 192.168.1.1`


## Bibliografia
* c++ referencia: https://en.cppreference.com/w/ cited [2024-03-10]
* Wikipedia, the free encyclopedia[online]: http://en.wikipedia.org/wiki/Pcap cited [2024-03-10] 
* ChatGPT[online]: https://chat.openai.com/ cited [2024-03-10] 



