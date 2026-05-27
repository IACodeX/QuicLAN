# QuicLAN

QuicLAN es una LAN virtual P2P para Windows basada en Wintun. Mantiene el discovery UDP por sala, STUN y trackers, y añade QUIC real como transporte preferido para tráfico unicast cuando el enlace QUIC está abierto.

## Arquitectura

```text
Discovery/control inicial:
  sala -> roomKey -> Hello cifrado -> UDP broadcast/candidates/trackers

Datos LAN:
  Wintun IPv4 packet
    -> ruta virtual por IP 10.88.x.x
    -> QUIC stream si es unicast y está listo
    -> UDP legacy cifrado como fallback y para broadcast/multicast
    -> peer remoto -> Wintun
```

El objetivo de esta edición es mantener simple el camino de LAN, quitar puentes específicos de juegos y dejar QUIC integrado sin convertirlo en punto único de fallo.

## Puertos por defecto

```text
UDP discovery/STUN/trackers/fallback: 51888
QUIC datos Wintun:                    51889
```

## Uso

```powershell
QuicLan.exe --room "familia-2026-frase-larga" --name "PC-Salon"
QuicLan.exe --room "familia-2026-frase-larga" --disable-quic
QuicLan.exe --room "familia-2026-frase-larga" --no-udp-data-fallback
```

Opciones principales:

```text
--room <texto>       Sala/clave compartida.
--name <nombre>      Nombre visible del peer.
--port <udp>         Puerto UDP discovery/fallback. Default: 51888.
--data-port <udp>    Puerto QUIC. Default: 51889.
--mtu <bytes>        MTU virtual. Rango: 576-1400.
--pak <bytes>        Límite de paquete. Rango: 576-1400.
--bst <n>            Ráfaga de envío. Rango: 1-256.
--prefix <ipv4>      Red virtual /16. Default: 10.88.0.0.
--no-trackers        Sólo discovery LAN/candidates.
--tracker <url>      Añade tracker UDP.
--verbose            Diagnóstico resumido.
--disable-quic       Usa sólo UDP legacy cifrado para datos.
--no-udp-data-fallback Descarta datos si QUIC no está listo.
```

Durante ejecución: `stat`, `pak 1000`, `bst 16`, `mtu 1200`, `reset`, `help`, `quit`.

## Qué se conserva

- Sala compartida con PBKDF2.
- Identidad ECDSA persistente.
- Hello cifrado y firmado.
- IP virtual automática por sala/peer/salt.
- STUN y trackers UDP.
- Wintun integrado.
- Control local por terminal.
- UDP legacy cifrado como fallback estable.

## Qué se limpió en esta edición

- Eliminado el puente específico de Minecraft/LAN advertisements.
- Eliminadas rutas/métricas multicast experimentales.
- Reducido el spam verbose de candidatos y rosters.
- QUIC vuelve a estar activo como mejora real para unicast, pero broadcast/multicast y fallback siguen por UDP.

## Seguridad

Los Hellos se cifran con una clave derivada de la sala y se firman con la identidad ECDSA del peer. Para QUIC, el certificado X.509 se genera desde esa identidad; el peer remoto se valida contra el `PeerId` esperado y además se intercambia una preface firmada `QLQ5`.

## Limitaciones

- No hay relay todavía; algunos NATs seguirán necesitando port-forwarding o fallback por tracker compatible.
- QUIC usa stream fiable; QUIC DATAGRAM sería el siguiente paso natural para paquetes IP puros.
- No hay lista persistente de peers autorizados/fingerprints.
- Esta entrega es una variante ultra-lean: se retiró la API HTTP local para reducir código y superficie de ataque; el control queda por terminal.
