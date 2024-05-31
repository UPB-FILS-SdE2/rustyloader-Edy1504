[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/emMZvU8G)
# SdE2 Devoir 3 Starter - Rusty Loader

## Solution

TODO Décrivez ici comment avez-vous résolu les devoirs. 
struct Segment reprezinta un segment in binarul ELF, cu atribute pentru adresa virtuala, dimensiunea memoriei, offset-ul fisierului, dimensiunea fisierului, indicatori si o referinta la fisier.
sigsegv_handler gestioneaza erorile de segmentare (SIGSEGV). Atunci cand apare o eroare de segmentare, acesta verifica daca adresa de eroare se incadrează în vreun segment incarcat.
In cazul in care adresa se afla in interiorul unui segment, calculeaza pagina necesara, citeste pagina din fisier si o mapeaza in memorie.
In cazul in care nu poate gestiona defectiunea (adresa nu se afla intr-un segment), imprima o eroare si iese.
exec deschide si citeste fisierul ELF, il analizeaza si ii extrage segmentele.
Aceasta stabileste segmentele cu adresele, dimensiunile si indicatoarele de acces, apoi instaleaza gestionarul de erori de segmentare.
Seteaza variabila globala SEGMENTS si apeleaza runner::exec_run pentru a incepe executia din punctul de intrare al fisierului ELF.
Functia main proceseaza argumentele din linia de comanda pentru a obține numele de fisier, apoi apeleaza functia exec.
SEGMENTE este o lista globala mutabila de segmente protejata de un Mutex, asigurand accesul in conditii de siguranta.