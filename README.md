# Darkly - Breach Report

## Breaches

| # | Breach | Flag |
|---|--------|------|
| 1 | AdminPanel | d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff |
| 2 | BruteForce | b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2 |
| 3 | CookieTampering | df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3 |
| 4 | FileUpload | 46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8 |
| 5 | HiddenFiles | d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466 |
| 6 | ImageSearchSQLi | f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188 |
| 7 | LocalFileInclusion | b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0 |
| 8 | PasswordRecovery | 1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0 |
| 9 | RedirectXSS | b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3 |
| 10 | SqlInjection | 10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5 |
| 11 | SurveyTampering | 03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa |
| 12 | UserAgentReferer | f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188 |
| 13 | XSSDataURI | 928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d |
| 14 | XSSStored | 0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e |

---

### AdminPanel
**Flag** : `d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff`

**Vulnerabilite** : Credentials exposes + mot de passe faible

**Methode** :
1. nikto detecte `/admin/index.php` et `/.htpasswd` accessibles publiquement
2. `curl http://192.168.1.103/whatever/` revele un fichier `.htpasswd` contenant `root:437394baff5aa33daa618be47b75cb49`
3. Le hash MD5 est cracke sur crackstation.net : `qwerty123@`
4. Connexion sur `/admin/index.php` via HTTP Basic Auth avec `root:qwerty123@`

**Fix** : Ne jamais exposer un `.htpasswd` publiquement. Utiliser bcrypt au lieu de MD5 pour hasher les mots de passe. Choisir des mots de passe forts.

---

### BruteForce
**Flag** : `b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2`

**Vulnerabilite** : Credentials faibles sur le formulaire de login (pas de rate limiting, mot de passe trivial)

**Methode** :
1. Via la SQL injection (SqlInjection), on liste toutes les bases de donnees
2. `Member_Brute_Force.db_default` contient une table avec `username` et `password`
3. `1 UNION SELECT username, password FROM Member_Brute_Force.db_default` extrait `admin:3bf1114a986ba87ed28fc1b5884fc2f8`
4. Hash MD5 cracke sur crackstation.net -> `shadow`
5. Connexion sur `/?page=signin` avec `admin:shadow`

**Fix** : Rate limiting sur les tentatives de login, mots de passe forts, ne pas stocker les passwords en MD5.

---

### CookieTampering
**Flag** : `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`

**Vulnerabilite** : Authentification basee sur un cookie non signe cote client

**Methode** :
1. En inspectant les cookies du site via DevTools, on trouve un cookie `I_am_admin` avec la valeur MD5 de "false" : `68934a3e9455fa72420237eb05902327`
2. Le site utilise ce cookie pour determiner si l'utilisateur est admin
3. On calcule le MD5 de "true" : `b326b5062b2f0e69046810717534cb09`
4. On remplace la valeur du cookie via DevTools
5. Le site nous accorde les droits admin et revele le flag

**Fix** : Ne jamais stocker l'etat d'authentification dans un cookie cote client sans signature cryptographique (HMAC). Utiliser des sessions cote serveur avec un identifiant de session aleatoire et imprevisible.

---

### FileUpload
**Flag** : `46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8`

**Vulnerabilite** : Unrestricted File Upload (OWASP A04)

**Methode** :
1. `/?page=upload` expose un formulaire d'upload qui valide uniquement le Content-Type HTTP, pas le contenu reel du fichier
2. N'importe quel fichier non-image uploade avec `Content-Type: image/jpeg` force declenche le flag
3. Creation d'un fichier quelconque : `echo '<?php system("id"); ?>' > shell.php`
4. Upload en forcant le Content-Type a `image/jpeg` via curl :
   `curl -F "MAX_FILE_SIZE=100000" -F "uploaded=@shell.php;type=image/jpeg" -F "Upload=Upload" "http://192.168.1.103/?page=upload"`
5. Le serveur accepte le fichier et retourne directement le flag

**Fix** : Verifier la vraie signature du fichier (magic bytes), pas uniquement le Content-Type. Stocker les fichiers uploades hors du webroot ou avec une extension neutre pour empecher leur execution par le serveur.

---

### HiddenFiles
**Flag** : `d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466`

**Vulnerabilite** : Information disclosure via robots.txt

**Methode** :
1. `nmap --script http-robots.txt 192.168.1.103` revele un fichier `robots.txt` avec 2 entrees Disallow : `/whatever` et `/.hidden`
2. Le robots.txt est cense dire aux crawlers de ne pas indexer ces chemins, mais il revele leur existence a un attaquant
3. `wget -r -np -l 10 -e robots=off http://192.168.1.103/.hidden/` crawle recursivement le repertoire
4. `find . -name "README" -exec grep -l "flag" {} \;` trouve le README contenant le flag parmi des centaines de faux

**Fix** : Ne jamais lister de chemins sensibles dans robots.txt. Si un repertoire doit etre inaccessible, le proteger cote serveur (auth, permissions) pas juste le cacher.

---

### ImageSearchSQLi
**Flag** : `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

**Vulnerabilite** : SQL Injection avec bypass de filtre quotes via encodage hexadecimal

**Methode** :
1. `/?page=searchimg` est vulnerable a la SQLi, la requete retourne 2 colonnes
2. Le serveur echappe les apostrophes (magic_quotes-like), empechant l'utilisation directe de noms de tables entre quotes
3. Contournement : encoder le nom de la table en hex (`list_images` -> `0x6c6973745f696d61676573`)
4. Enumeration via `information_schema.schemata` -> decouverte de la base `Member_images`
5. `1 UNION SELECT title, comment FROM Member_images.list_images` dump la table
6. Ligne cachee "Hack me ?" contient le hash MD5 `1928e8083cf461a51303633093573c46`
7. Crack sur crackstation.net -> `albatroz` -> SHA256 -> flag

**Fix** : Utiliser des prepared statements. Restreindre les privileges SQL et l'acces a `information_schema`.

---

### LocalFileInclusion
**Flag** : `b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0`

**Vulnerabilite** : Local File Inclusion (LFI) via path traversal sur le parametre `page`

**Methode** :
1. Le site charge dynamiquement des fichiers avec `?page=...`, pattern typique d'un include PHP
2. Test de traversal : `/?page=../../../../../../../../etc/passwd`
3. Le serveur inclut le fichier cible et retourne le flag

**Fix** : Ne jamais inclure directement une valeur contrôlée par l'utilisateur. Utiliser une whitelist stricte de pages autorisées (mapping fixe), normaliser le chemin, et bloquer toute séquence de traversal (`../`) côté serveur.


Online tools that we used : 
https://crackstation.net
CyberChef:
https://gchq.github.io/CyberChef/#recipe=SHA2('256',1,160)MD5(/disabled)&input=YWxiYXRyb3o
