## 01 Emailextractor, extract.pl, btw21.txt, (emails.txt)
Nimmt die Datei btw21.txt und extrahiert alles an Landkreisen und Mailadressen, was auffindbar ist. Die Mailadressen werden mithilfe eines DNS MX checks auf (grobe) Gültigkeit geprüft und in einer sqlite Datenbank mit Zuordnung zum Landkreis und Bundesland abgespeichert.
Sofern eine Date emails.txt existiert, wird statt der btw21.txt diese verwendet. Die emails.txt enthält einfach in jeder Zeile eine zu prüfende Emailadresse. Gedacht als Einstieg in einen eigenen schnellen Scan.

## 02 Scanner, scan.pl, openssl.cnf
Nimmt sich jede Maildomain aus der sqlite Datenbank vor und ermittelt alle MX Einträge, und für jeden MX Eintrag jede IPv4 dieses MX. Dann wird mithilfe von openssl s_client ein Verbindungsversuch mit smtp und STARTTLS durchgeführt und die Ausgaben dieses Versuches werden in der sqlite Datenbank gespeichert, unter Zuordnung, zu welchen Maildomains dieser Scan dieses Mailservers gehört. Dabei wird die im gleichen Verzeichnis liegende Konfiguration der openssl.cnf genutzt, um der Debian 2048 bit Einstellung zu entgehen. Es wird eine Deduplizierung der Mailserver durchgeführt, so dass jeder MX+IP nur einmal gescannt wird.

## 03 Eval, eval.pl
Prüft die in der sqlite DB gespeicherten Ausgaben des openssl Verbindungsversuches und extrahiert konkrete Informationen über die Verbindung und speichert diese ebenso in der sqlite DB.

Dabei werden folgende Kürzel verwendet:

ER(0): Es konnte keine Verbindung hergestellt werdem

ER(1): Verbindung konnte aufgebaut werden, aber kein TLS ausgehandelt werden

HN: Der Hostname des Zertifikates stimmt nicht mit dem des Servers überein

EX: Das Server Zertifikat ist abgelaufen

LO: Das Server Zertifikat hat eine Restlaufzeit von über 4 Jahren

SS: Das Server Zertifikat, oder eines in der Kette, ist selbst signiert

VE(X): Das Server Zertifikat kann nicht mit den vertrauenswürdigen CAs der Debian Distribution verifiziert werden. X gibt die Anzahl der Zertifikate in der Kette an.

CB(X): Das Server Zertifikat hat eine Schlüsselstärke von <2048bit. X gibt die Schlüsselstärke an.

HS(X): Das Server Zertifikat hat einen SHA1 oder MD5 Hash. X gibt den Hashtyp an.

TS(X): Es konnte nur eine TLS Version <1.2 ausgehandelt werden. X gibt die Version an.
