Actúa como un ingeniero senior de seguridad ofensiva y desarrollo en Python. Estoy desarrollando la Fase 5 (UD2 - El agente de enumeración) del proyecto «El informático fantasma» sobre el repositorio `aap-base` para una auditoría autorizada en un laboratorio aislado de clase.

Te adjunto los ficheros reales de mi proyecto:
1. `herramientas/tus_herramientas_enumeracion.py` (plantilla con los TODO y el decorador `@protegida`)
2. `herramientas/escaneo.py` (funciones base ya implementadas para lanzar nmap, guardar evidencias y consultar NVD, EPSS y KEV)
3. `herramientas/whois.py` (referencia del estilo del proyecto: sin shell, timeouts y errores como texto)
4. `scope.txt` (alcance autorizado de nuestra práctica, con nuestra red objetivo y las IPs excluidas con `!` que descartamos en la práctica manual)

### Objetivo
Implementa ÚNICAMENTE las tres herramientas de `herramientas/tus_herramientas_enumeracion.py` (`nmap_descubrir`, `nmap_servicios` y `cve_lookup`) siguiendo todos sus `TODO` y reutilizando las funciones de `herramientas/escaneo.py` sin reescribirlas[cite: 6, 9].

### Restricciones técnicas y de seguridad (obligatorias)
1. **Archivos intocables:** No modifiques ni propongas cambios en `motor/`, `alcance/`, `herramientas/escaneo.py`, `enumerar.py`, `instrucciones-enumeracion.md` ni en los ficheros de la UD1 (`lanzar.py`, `tus_herramientas.py`, `instrucciones.md`)[cite: 6, 9].
2. **Control de alcance (`@protegida`):** Mantén intacto el decorador `@protegida` en las tres funciones[cite: 9].
3. **Sin parámetros extra:** No añadas parámetros de opciones o flags de `nmap`[cite: 7, 9]. Las opciones (`-sT -sV -p- -T3`, sin scripts y solo TCP) las fija `escaneo.py`[cite: 7].
4. **Ejecución segura:** Prohibido usar `shell=True` o subprocesos propios[cite: 9, 10]. Captura excepciones y timeouts devolviendo siempre strings descriptivos con prefijo `ERROR:` o avisos claros, sin romper la ejecución del agente[cite: 9].
5. **Gestión de contexto y evidencias:** Guarda siempre la salida completa (XML de nmap o respuesta de API) en la carpeta de evidencias usando las funciones de `escaneo.py` para obtener su código (`E01`, `E02`...), y devuelve al agente **únicamente un resumen corto y estructurado junto con el código de evidencia**, nunca el XML ni JSON en bruto[cite: 6, 9].
6. **Defensa frente a Prompt Injection:** No elimines ni alteres el saneamiento y acotado de banners o descripciones de CVE que realiza `escaneo.py`[cite: 7].

### Especificación funcional de cada herramienta

#### 1. `nmap_descubrir(red: str) -> str`
- **Validación previa:** Verifica con `escaneo.py` (ej. `red_ipv4`) que `red` sea una red IPv4 CIDR válida y bien escrita; si recibe un nombre de dominio, una IP suelta mal formateada o un formato inválido, devuelve un error explícito antes de escanear[cite: 7, 9].
- **Gestión de exclusiones del `scope.txt`:** Ten en cuenta que `scope-guard` bloquea cualquier rango CIDR que contenga una IP excluida (`!IP`) en `scope.txt`[cite: 5]. Asegúrate de que el **docstring** instruya claramente al agente: *si al consultar la red `/24` completa recibe `BLOQUEADO` por contener IPs excluidas, debe dividir el descubrimiento en subredes CIDR más pequeñas que omitan esas IPs excluidas*[cite: 5, 7].
- **Escaneo incompleto:** Comprueba mediante `escaneo_incompleto` si `nmap` agotó el tiempo; si no terminó, indícalo explícitamente («escaneo incompleto / no terminó, puede haber más equipos») y nunca digas que hay 0 equipos vivos[cite: 7, 9, 10].
- **Salida:** Lista limpia de IPs vivas detectadas + código de evidencia (`Evidencia: E0X (...)`)[cite: 6, 10].

#### 2. `nmap_servicios(host: str) -> str`
- **Validación previa:** Verifica que `host` sea una única dirección IPv4 válida (rechaza explícitamente rangos CIDR como `10.88.0.0/25`, nombres de dominio o entradas malformadas)[cite: 7, 10].
- **Escaneo incompleto:** Si `nmap` no termina en plazo, avisa claramente de que el escaneo quedó incompleto («no terminó»)[cite: 7].
- **Salida:** Resumen compacto con el total de puertos TCP abiertos, una línea por puerto (`puerto/tcp | servicio | versión`) y el código de evidencia (`Evidencia: E0X (...)`)[cite: 6, 7].

#### 3. `cve_lookup(host: str, puerto: int) -> str`
- **Firma estricta:** Recibe SOLO `host` y `puerto` (nunca producto ni versión, para evitar que el modelo invente versiones o consulte servicios no escaneados)[cite: 7].
- **Validación previa:** Comprueba que `host` es una IPv4 válida, que `puerto` es un entero válido (1-65535) y recupera el producto y la versión exactos del escaneo previo guardado en evidencias[cite: 7]. Si el equipo o puerto no se ha escaneado previamente o no tiene versión identificada, devuelve un aviso claro indicando que no hay versión registrada para consultar[cite: 7, 8, 10].
- **Fidelidad de datos («No lo sé» no es «no»):** Si NVD, EPSS o KEV no responden o no tienen registro para un CVE, muestra literalmente `sin dato` (nunca `no` ni `False`)[cite: 7, 9]. Si la consulta en

En la auditoría manual quedaron documentadas ocho IP activas, de 172.17.0.3 a 172.17.0.10 , esas son las que hay que escanear, todo lo demas no hay que escanearlo ni nuestra propia maquina. Dentro de la carpeta encontrar dos pdfs los cuales estan las indicaciones del proyecto llamados TEORIA EL AGENTE.pdf y  Proyecto 2 · El informático fantasma - EL AGENTE.pdf , esto es lo unico que tendremos que entregar.
agentes/                  # una carpeta por integrante, con lo que hizo su agente
│   ├── nombre-apellido-1/
│   │   ├── informe.md        # el informe que generó su agente
│   │   └── trazas/           # una traza por ejecución, con la fecha como nombre
│   │       └── 2026-11-19_202727.jsonl