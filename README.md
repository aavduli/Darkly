# Darkly

---
Breach 1 - HiddenFiles
flag: d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466
method: robots.txt -> /.hidden -> wget récursif -> find README
---
Breach 2 - Admin panel
flag: d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff
method: nikto -> /admin/index.php -> HTTP Basic Auth -> .htpasswd dans /whatever -> crack MD5 hash
