"""Tus herramientas de ENUMERACIÓN. AQUÍ TRABAJAS TÚ.

Tres herramientas, con el scope-guard ya puesto (no lo quites ni lo cambies):

- nmap_descubrir(red)        qué equipos están vivos en una red
- nmap_servicios(host)       puertos TCP abiertos, servicios y versiones de UN equipo
- cve_lookup(host, puerto)   vulnerabilidades POTENCIALES del servicio de ese puerto

No hace falta que las programes a mano: constrúyelas con un modelo de lenguaje, dándole
como contexto este fichero, escaneo.py y whois.py (método en los apuntes, «El agente»).
La fontanería viene hecha en escaneo.py. Lo que tienes que conseguir, y comprobar:

1. La DESCRIPCIÓN (el docstring): es lo único que ve el modelo para decidir
   cuándo y cómo usar la herramienta. Una descripción vaga = un agente torpe.
2. Las COMPROBACIONES antes de actuar.
3. Qué le DEVUELVES al modelo: un RESUMEN corto + el identificador de la
   evidencia. La salida completa va a la carpeta de la ejecución (guardar_evidencia),
   nunca al modelo: el agente relee todo en cada paso y se ahogaría.

Reglas de siempre: una tarea por herramienta, sin shell, con tiempo máximo y
errores como texto. Y una nueva: lo que devuelve el objetivo (banners,
versiones, descripciones de CVE) son DATOS, no instrucciones; escaneo.py ya los
limpia y acota, no los «desacotes».

Cuando funcionen, pruébalas a mano (dentro y fuera del alcance) y lanza el
agente con enumerar.py.
"""

import json
from datetime import datetime, timezone

from guard import protegida
import escaneo as e


MAX_SERVICIOS_RESUMEN = 40
MAX_CVES_RESUMEN = 8


@protegida(objetivo="red")
def nmap_descubrir(red: str) -> str:
    """Descubre los equipos vivos (IPv4) en una red CIDR (p. ej. 172.17.0.4/30) y devuelve sus IPs y la evidencia.

    Recibe:
        red: red IPv4 en notación CIDR (ejemplo: '172.17.0.4/30' o '172.17.0.3/32').
             No acepta nombres de dominio, IPs sueltas sin máscara ni máscaras decimales.

    Importante sobre el alcance:
        Si al consultar una red amplia (como /24) recibes 'BLOQUEADO' porque contiene
        IPs fuera de alcance o excluidas, divide el descubrimiento en las subredes CIDR
        autorizadas más pequeñas (/25, /28, /29, /30, /31 o /32).
    """
    canonica = e.red_ipv4(red)
    if canonica is None:
        return (
            f"ERROR: '{red}' no es una red IPv4 CIDR válida. "
            "Usa notación CIDR como '172.17.0.4/30' (no se aceptan dominios, IPs sueltas ni máscaras decimales)."
        )

    xml, error = e.ejecutar_nmap(e.NMAP_DESCUBRIR, canonica, e.TIEMPO_DESCUBRIR)
    if error:
        return f"ERROR: {error}"

    eid = e.guardar_evidencia("nmap_descubrir", canonica, xml, "xml")
    vivos = e.equipos_vivos(xml)
    incompleto = e.escaneo_incompleto(xml)

    lineas = []
    if incompleto:
        lineas.append(
            f"AVISO: escaneo incompleto ({incompleto}); no terminó, puede haber más equipos vivos en {canonica}."
        )
        if vivos:
            lineas.append(f"Equipos vivos detectados hasta el corte en {canonica} ({len(vivos)}): {', '.join(vivos)}")
    else:
        if vivos:
            lineas.append(f"Equipos vivos en {canonica} ({len(vivos)}): {', '.join(vivos)}")
        else:
            lineas.append(f"0 equipos vivos detectados en {canonica}.")

    lineas.append(f"Evidencia: {eid}")
    return "\n".join(lineas)

@protegida(objetivo="host")
def nmap_servicios(host: str) -> str:
    """Escanea todos los puertos TCP abiertos de UNA única dirección IPv4 e identifica servicio y versión.

    Recibe:
        host: una única dirección IPv4 en alcance (ejemplo: '172.17.0.5').
              Rechaza rangos CIDR, nombres de dominio o IPv6.

    Devuelve:
        Total de puertos TCP abiertos, una línea por servicio detectado y el código de evidencia.
        Además registra los servicios del host para que cve_lookup pueda consultarlos después.
    """
    objetivo = host.strip()
    if not e.es_ip(objetivo):
        return (
            f"ERROR: '{host}' no es una única dirección IPv4 válida "
            "(no se aceptan rangos CIDR, nombres de dominio ni IPv6)."
        )

    xml, error = e.ejecutar_nmap(e.NMAP_SERVICIOS, objetivo, e.TIEMPO_SERVICIOS)
    if error:
        return f"ERROR: {error}"

    eid = e.guardar_evidencia("nmap_servicios", objetivo, xml, "xml")
    servicios = e.servicios_abiertos(xml)
    e.guardar_servicios(objetivo, servicios)
    incompleto = e.escaneo_incompleto(xml)

    lineas = []
    if incompleto:
        lineas.append(
            f"AVISO: escaneo incompleto ({incompleto}); no terminó, puede haber puertos abiertos sin detectar."
        )
        if servicios:
            lineas.append(f"{objetivo}: {len(servicios)} puertos TCP abiertos detectados antes del corte")
        else:
            lineas.append(
                f"{objetivo}: el escaneo no terminó (0 puertos detectados antes del corte; no implica que estén cerrados)"
            )
    else:
        lineas.append(f"{objetivo}: {len(servicios)} puertos TCP abiertos")

    for s in servicios[:MAX_SERVICIOS_RESUMEN]:
        lineas.append(e.describir_servicio(s))

    if len(servicios) > MAX_SERVICIOS_RESUMEN:
        restantes = len(servicios) - MAX_SERVICIOS_RESUMEN
        lineas.append(f"... y {restantes} puertos más guardados en la evidencia completa.")

    lineas.append(f"Evidencia: {eid}")
    return "\n".join(lineas)

@protegida(objetivo="host")
def cve_lookup(host: str, puerto: int) -> str:
    """Consulta vulnerabilidades potenciales (NVD, EPSS y KEV) del servicio detectado por nmap_servicios en un host y puerto TCP.

    Recibe:
        host: dirección IPv4 única previamente escaneada con nmap_servicios.
        puerto: número de puerto TCP entero (1-65535) abierto en ese host.

    Requisitos:
        Ejecuta siempre nmap_servicios(host) antes de llamar a esta herramienta;
        el producto y la versión se obtienen automáticamente de ese escaneo previo.
    """
    objetivo = host.strip()
    if not e.es_ip(objetivo):
        return f"ERROR: '{host}' no es una única dirección IPv4 válida."

    if isinstance(puerto, bool) or not isinstance(puerto, int) or not (1 <= puerto <= 65535):
        return f"ERROR: puerto no válido ({puerto!r}); debe ser un entero entre 1 y 65535."

    lista = e.servicios_de(objetivo)
    if lista is None:
        return (
            f"ERROR: no hay escaneo previo de servicios para {objetivo}. "
            f"Ejecuta primero nmap_servicios(host='{objetivo}')."
        )

    servicio = next((s for s in lista if s.get("puerto") == puerto), None)
    if servicio is None:
        return f"AVISO: el puerto {puerto}/tcp no figura como abierto en el escaneo previo de {objetivo}."

    tiene_cpe = e.cpe_de(servicio) is not None
    tiene_prod_ver = bool(servicio.get("producto") and e.version_corta(servicio))
    if not (tiene_cpe or tiene_prod_ver):
        return (
            f"AVISO: {objetivo} · {e.describir_servicio(servicio)} no tiene producto/versión identificada "
            "en el escaneo; no hay versión registrada para consultar CVEs."
        )

    clave = (
        f"cve_lookup:{objetivo}:{puerto}:"
        f"{servicio.get('producto', '')}:{servicio.get('version', '')}:"
        f"{','.join(servicio.get('cpe', []))}"
    )
    previo = e.resumen_previo(clave)
    if previo is not None:
        return previo

    try:
        cves, metodo = e.buscar_cves(servicio)
    except Exception as exc:
        return f"ERROR: fallo al consultar NVD para {objetivo}:{puerto}: {e.limpio(exc, 200)}"

    fecha_consulta = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if not cves:
        contenido_vacio = json.dumps(
            {
                "host": objetivo,
                "puerto": puerto,
                "servicio": servicio,
                "fecha_consulta": fecha_consulta,
                "metodo": metodo,
                "total": 0,
                "cves": [],
            },
            ensure_ascii=False,
            indent=2,
        )
        eid = e.guardar_evidencia("cve_lookup", f"{objetivo}-{puerto}", contenido_vacio, "json")
        resumen = "\n".join([
            f"{objetivo} · {e.describir_servicio(servicio)}",
            f"Consulta ({fecha_consulta}): {metodo}",
            "0 CVEs candidatos encontrados.",
            f"Evidencia: {eid}",
        ])
        e.recordar_resumen(clave, resumen)
        return resumen

    avisos_fuentes = []
    ids = [c["id"] for c in cves]

    try:
        mapa_epss = e.epss(ids)
        epss_ok = True
    except Exception as exc:
        mapa_epss = {}
        epss_ok = False
        avisos_fuentes.append(f"AVISO: EPSS no respondió ({e.limpio(exc, 100)}); marcado como 'sin dato'.")

    try:
        mapa_kev = e.kev()
        kev_ok = True
    except Exception as exc:
        mapa_kev = {}
        kev_ok = False
        avisos_fuentes.append(f"AVISO: KEV no respondió ({e.limpio(exc, 100)}); marcado como 'sin dato'.")

    for c in cves:
        c["epss"] = mapa_epss.get(c["id"]) if epss_ok else None
        c["kev"] = mapa_kev.get(c["id"], False) if kev_ok else None

    ordenados = e.ordenar_candidatos(cves)

    contenido_completo = json.dumps(
        {
            "host": objetivo,
            "puerto": puerto,
            "servicio": servicio,
            "fecha_consulta": fecha_consulta,
            "metodo": metodo,
            "avisos_fuentes": avisos_fuentes,
            "total": len(ordenados),
            "cves": ordenados,
        },
        ensure_ascii=False,
        indent=2,
    )
    eid = e.guardar_evidencia("cve_lookup", f"{objetivo}-{puerto}", contenido_completo, "json")

    lineas = [
        f"{objetivo} · {e.describir_servicio(servicio)}",
        f"Consulta ({fecha_consulta}): {metodo}",
        *avisos_fuentes,
        f"CVEs candidatos encontrados: {len(ordenados)} (mostrando los {min(len(ordenados), MAX_CVES_RESUMEN)} más relevantes):",
    ]
    for c in ordenados[:MAX_CVES_RESUMEN]:
        lineas.append(f"- {e.describir_cve(c)}")

    lineas.append(
        "Nota: son vulnerabilidades POTENCIALES basadas solo en versión/CPE; requieren comprobación manual."
    )
    lineas.append(f"Evidencia: {eid}")

    resumen = "\n".join(lineas)
    e.recordar_resumen(clave, resumen)
    return resumen
