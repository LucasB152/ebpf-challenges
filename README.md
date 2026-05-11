# eBPF Challenges

> Project 1 — INFO0940-1: Operating Systems  
> University of Liège | Prof. L. Mathy, B. Knott, G. Gain

---

## Table des matières

1. [Challenge 1 : Anti-Debugger](#challenge-1--anti-debugger)
2. [Challenge 2 : Protected File](#challenge-2--protected-file)
3. [Challenge 3 : Ciphered Writes](#challenge-3--ciphered-writes)
4. [Challenge 4 : Forking Prevention](#challenge-4--forking-prevention)
5. [Challenge 5 : Page Fault Frequency Monitoring](#challenge-5--page-fault-frequency-monitoring)

---

## Challenge 1 — Anti-Debugger

### Description

L'objectif est de protéger un jeu du pendu (terminal-based) contre l'utilisation d'un débogueur comme `gdb`. Le programme eBPF doit détecter si le processus du jeu est en cours de débogage (i.e. lancé via `gdb run`) et le terminer immédiatement, avant même que le joueur n'ait la chance d'entrer une lettre.

La technique utilisée est un **uprobe** : une sonde attachée à une fonction du binaire du jeu, qui se déclenche lors de l'exécution de cette fonction. Si le processus parent est `gdb`, le jeu est tué.

Le code eBPF à compléter se trouve dans `antidebug/src/`.

### Lancer

Dans un terminal, charger le programme eBPF (depuis `antidebug/src/`) :

```bash
make
sudo ./prog
```

Dans un autre terminal, lancer le jeu normalement (depuis `antidebug/hangman/`) :

```bash
make
./hangman
# → doit fonctionner normalement
```

### Tester

Lancer le jeu sous `gdb` :

```bash
gdb ./hangman
(gdb) run
# → le jeu doit être immédiatement terminé avant toute interaction
(gdb) quit
```

**Comportement attendu :** dès que `run` est tapé dans `gdb`, le processus du jeu est tué. Si `gdb` est ouvert mais que `run` n'est pas encore utilisé, le jeu ne doit pas être affecté.

---

## Challenge 2 — Protected File

### Description

Un programme suspect nommé `scanner` lit un fichier puis écrase son contenu avec `"You have been pwned!"`. L'objectif est d'implémenter un programme eBPF utilisant le mécanisme **eBPF LSM (Linux Security Modules)** pour empêcher tout processus nommé `scanner` d'écrire dans un fichier, sans le tuer — le processus doit continuer à tourner mais toutes ses tentatives d'écriture doivent être refusées.

> ⚠️ BPF LSM n'est pas activé par défaut sur la VM. Il faut l'activer manuellement.

Le programme malveillant est dans `protected_file/scanner`.  
Le code eBPF à compléter se trouve dans `protected_file/src/`.

### Lancer

Charger le programme eBPF :

```bash
make
sudo ./prog
```

### Tester

Sans le programme eBPF chargé :

```bash
make
echo "Cool Recipe: I love cake" > recipe.txt
./scanner recipe.txt
cat recipe.txt
# → "You have been pwned!"
```

Avec le programme eBPF chargé :

```bash
make
echo "Cool Recipe: I love cake" > recipe.txt
./scanner recipe.txt
```

**Sortie attendue :**

```
Using provided file: recipe.txt
Read: Cool Recipe: I love cake
Error when trying to write: Operation not permitted
Read after write: Cool Recipe: I love cake
```

Le fichier `recipe.txt` doit rester inchangé. Le processus `scanner` ne doit pas être tué, seulement bloqué dans ses écritures.

---

## Challenge 3 — Ciphered Writes

### Description

L'objectif est d'intercepter les appels système `write()` d'un processus nommé `echo_test` et d'appliquer un **chiffrement par décalage César** sur les données écrites, de façon transparente au niveau du noyau. Seuls les caractères alphabétiques (`A-Z`, `a-z`) sont chiffrés ; les chiffres, la ponctuation et les espaces restent inchangés. Le chiffrement ne doit s'appliquer que lorsque `echo_test` écrit dans un fichier (pas sur stdout ni stderr).

Le décalage est configurable via l'argument `--shift` (défaut : 3, appliqué modulo 26).

### Installation

Le code eBPF à compléter se trouve dans `ciphered/src/`.

### Lancer

Avec le décalage par défaut (3) :

```bash
make
sudo ./prog
```

Avec un décalage personnalisé :

```bash
make
sudo ./prog --shift 10
```

### Tester

Dans un autre terminal, lancer le programme de test :

```bash
make
./echo_test
```

**Sortie attendue avec `--shift 3` :**

```bash
$ cat output.txt
Khoor123
# "Hello" → "Khoor", "123" inchangé
```

**Sortie attendue avec `--shift 10` :**

```bash
$ cat output.txt
Rovvy123
# "Hello" → "Rovvy"
```

Sans le programme eBPF chargé, `output.txt` doit contenir `Hello123`.

---

## Challenge 4 — Forking Prevention

### Description

Un programme nommé `forking` crée en boucle des processus enfants via `fork()` (qui utilise le syscall `clone` sous Linux). Sans contrôle, cela peut mener à un déni de service par saturation du système. L'objectif est d'implémenter un programme eBPF qui applique une **politique de rate-limiting** sur la création de processus enfants du processus `forking`.

#### Politique (fenêtre glissante)

Un enfant est **tué** si la différence de temps entre sa création et celle de l'enfant créé *n* positions avant lui (dans la liste des enfants ayant survécu) est inférieure à *t* secondes.

- Les *n* premiers enfants sont toujours autorisés (fenêtre pas encore pleine).
- Un enfant tué n'entre pas dans la fenêtre ; la comparaison suivante se fait toujours par rapport au même ancien enfant.
- Le programme ne doit cibler que les enfants d'un processus nommé `"forking"` pour ne pas perturber le reste du système.

Les paramètres configurables sont :
- `--n_process` : taille de la fenêtre (défaut : 1, max : 32)
- `--time_separation_sec` : délai minimum en secondes (défaut : 1)

### Installation

Le code eBPF à compléter se trouve dans `fork/src/`.

### Lancer

```bash
make
sudo ./prog --n_process 1 --time_separation_sec 1
```

### Tester

Dans un autre terminal :

```bash
make
./forking
```

**Sortie attendue (exemple avec `--n_process 1 --time_separation_sec 1`) :**

```
Main process PID 4846 starting, creating 100 children
- Child process created with PID 4847 (parent 4846)
- Child process created with PID 4852 (parent 4846)
...
Main process PID 4846 waiting for children to finish...
```

Avec `n=1` et `t=1s`, une nouvelle ligne s'affiche environ une fois par seconde (chaque enfant doit être créé au moins 1 seconde après le précédent). Le nombre total d'enfants créés avec succès sera bien inférieur à 100.

On peut expérimenter avec différentes valeurs :

```bash
sudo ./prog --n_process 5 --time_separation_sec 2
```

---

## Challenge 5 — Page Fault Frequency Monitoring

### Description

Le programme eBPF surveille la **fréquence de page faults (PFF)** d'un processus nommé `page_fault_gen` et notifie l'espace utilisateur via un **perf buffer** quand la fréquence sort d'une plage acceptable [L, U] sur une fenêtre temporelle de *T* millisecondes.

Messages envoyés :
- `"PFF too high for process with PID %d"` si plus de `U * T` page faults se produisent dans la fenêtre.
- `"PFF too low for process with PID %d"` si moins de `L * T` page faults se produisent dans la fenêtre.

La détection du dépassement haut est **event-driven** (déclenchée à chaque page fault). La détection du seuil bas nécessite un mécanisme temporel côté **user space** (avec `CLOCK_MONOTONIC`, comme `bpf_ktime_get_ns()`).

Paramètres configurables :
- `--upper_bound_freq_ms` : seuil haut en page faults/ms (défaut : 100)
- `--lower_bound_freq_ms` : seuil bas en page faults/ms (défaut : 10)
- `--time_window_ms` : durée de la fenêtre en ms (défaut : 50). Contrainte : `upper_bound_freq_ms * time_window_ms <= 10000`.

### Installation

Le code eBPF à compléter se trouve dans `page_faults/src/`.

### Lancer

```bash
# Terminal 1 : charger le programme eBPF (redirige la sortie pour éviter le flood)
make
sudo ./prog --lower_bound_freq_ms 20 --upper_bound_freq_ms 100 --time_window_ms 10 > /tmp/ch5_output
```

```bash
# Terminal 2 : lancer le générateur de page faults
make
./page_fault_gen <min_frequency> <max_frequency> <period_ms>
```


### Tester

Exemple avec une oscillation entre 10 et 110 page faults/ms :

```bash
# Terminal 2
make
./page_fault_gen 10 110 1000
```

Après quelques secondes, arrêter le programme eBPF (`Ctrl+C`) et consulter la sortie :

```bash
cat /tmp/ch5_output | uniq
```

**Sortie attendue :**

```
PFF monitor: lower=20, upper=100, window=10ms
Monitoring started (filtering by process name). Press Ctrl+C to stop.
PFF too high for process with PID 35180
PFF too low for process with PID 35180
[...]
PFF too high for process with PID 35180
PFF too low for process with PID 35180
```

Les alternances `too high` / `too low` correspondent aux phases hautes et basses de l'oscillation triangulaire du générateur. Il est normal de voir plusieurs messages identiques consécutifs ; `uniq` permet de les dédupliquer.

Pour tester un cas constant :

```bash
./page_fault_gen 50 50 1000   # fréquence fixe à 50 pf/ms
```

---

## Notes générales

- Tous les programmes eBPF doivent être lancés avec `sudo`.
- Le code eBPF de chaque challenge se trouve dans le sous-dossier `src/` de l'archive correspondante.
- Il n'était pas nécessaire de gérer les race conditions dans ce projet.
