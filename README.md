# QuicLAN v5.5.4

**LAN virtual P2P para Windows con lobby, Wintun, discovery UDP, trackers, fallback UDP cifrado y QUIC real para datos cuando el enlace esta disponible.**

QuicLAN intenta que crear una LAN privada entre amigos sea parecido a entrar a un lobby de juego: pones un nombre, pones una sala, ves quien esta dentro, decides si crear una LAN modo red o modo server, y los demas se unen cuando quieran.

> Estado de esta version: v5.5.4 es una version experimental jugable/refactorizada. La base viene de QuicLanRewrite v5.2, pero ahora tiene lobby, propuestas de LAN, paneles separados, modo red/server y mejor diagnostico. No es todavia una version final estable.

---

## Indice

- [Cambios de v5.5.4](#cambios-de-v554)
- [Idea general](#idea-general)
- [Que problema resuelve](#que-problema-resuelve)
- [Conceptos clave](#conceptos-clave)
- [Requisitos](#requisitos)
- [Instalacion y compilacion](#instalacion-y-compilacion)
- [Uso rapido](#uso-rapido)
- [Las 4 ventanas](#las-4-ventanas)
- [Flujo normal de uso](#flujo-normal-de-uso)
- [Modo lobby](#modo-lobby)
- [Modo red](#modo-red)
- [Modo server](#modo-server)
- [Propuestas de LAN](#propuestas-de-lan)
- [Sistema de listo / no listo](#sistema-de-listo--no-listo)
- [IPs virtuales](#ips-virtuales)
- [IP custom](#ip-custom)
- [Reconexiones y fantasmas](#reconexiones-y-fantasmas)
- [Transporte: UDP, QUIC y fallback](#transporte-udp-quic-y-fallback)
- [Trackers y discovery](#trackers-y-discovery)
- [Comandos de la terminal principal](#comandos-de-la-terminal-principal)
- [Flags de arranque](#flags-de-arranque)
- [Ajustes principales](#ajustes-principales)
- [Seguridad](#seguridad)
- [Arquitectura interna](#arquitectura-interna)
- [Paneles internos](#paneles-internos)
- [Troubleshooting](#troubleshooting)
- [Preguntas frecuentes](#preguntas-frecuentes)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Roadmap sugerido](#roadmap-sugerido)
- [Glosario](#glosario)

---

## Cambios de v5.5.4

Esta revision no cambia la idea del proyecto; corrige detalles internos donde la implementacion podia comportarse distinto a lo esperado:

- El `SessionId` de la LAN activa ahora se usa para decidir si un peer pertenece realmente a esa sesion antes de enviarle trafico LAN.
- El estado de lobby/LAN se reemite periodicamente como snapshot para reducir desincronizaciones por perdida UDP.
- Broadcast y multicast se envian por fanout a los peers de la sesion y ahora pueden preferir QUIC si el enlace QUIC ya esta abierto; si no, caen al fallback UDP cifrado cuando esta permitido.
- `LobbyStatus` ya no debe pisar rutas/IPs validadas por `hello`/`ip-claim`.
- La combinacion `--disable-quic` + `--no-udp-data-fallback` se rechaza porque dejaria los datos IP sin transporte.
- La serializacion de opciones preserva mejor trackers personalizados y `--no-trackers` al relanzar.
- El salt `0` ya no queda como caso ambiguo para IP custom.
- Las colas de envio ya no descartan paquetes antiguos silenciosamente sin poder contarlos.

---

## Idea general

QuicLAN crea una red virtual entre varias maquinas Windows. Cada usuario entra a una **sala** compartida. Al entrar a la sala, todavia no entra automaticamente a la LAN. Primero aparece en un **lobby**. Desde ese lobby se puede crear una LAN activa en uno de dos modos:

1. **Modo red**: todos los usuarios dentro de la LAN intentan conectarse entre todos.
2. **Modo server**: una persona actua como host/coordinador y los demas se conectan solo a esa persona.

La idea es separar dos cosas:

```text
Sala / Lobby = donde la gente se encuentra, habla y se organiza.
LAN activa   = la red virtual real, como si fuera una partida dentro de la sala.
```

Esto evita que, por poner la misma sala, todos entren automaticamente en una LAN sin querer. Tambien permite que alguien este mirando la sala sin entrar todavia a la red virtual.

---

## Que problema resuelve

QuicLAN sirve para casos como:

- Jugar juegos LAN entre amigos por Internet.
- Montar una red privada temporal sin configurar router manualmente.
- Probar servicios locales entre PCs como si estuvieran en una misma red.
- Hacer una party/lobby simple donde uno hostea y los demas se unen.
- Usar una LAN virtual simple sin montar una VPN pesada.

Ejemplo mental tipo Minecraft:

```text
Pedro crea sala: survival123
Ana entra a la misma sala.
Los dos se ven en lobby.
Pedro propone SERVER porque el mundo esta en su PC.
Ana da ready.
Pedro escribe start.
Ana entra a la LAN y se conecta a la IP virtual de Pedro.
Carlos entra tarde, ve que ya hay server activo y decide unirse.
```

---

## Conceptos clave

### Sala

Texto compartido que todos escriben igual. Funciona como clave de grupo/discovery. Ejemplo:

```text
sala1234
familia-2026-frase-larga
minecraft viernes noche
```

Recomendacion: usar una frase larga. Una sala corta es facil de adivinar.

### Nombre visible

Nombre humano que se muestra en lobby. Es obligatorio. QuicLAN no debe usar automaticamente el nombre del PC porque puede repetirse o ser feo.

Ejemplo:

```text
Pedro Minecraft
Ana Portatil
Carlos
```

### Lobby

Estado inicial de la sala. Sirve para ver gente, chatear, organizarse, proponer LAN, marcar listo y ver pings/estado.

### LAN activa

La red virtual real. Solo existe cuando alguien la inicia. Puedes estar en la sala/lobby sin estar dentro de la LAN.

### Modo red

Todos con todos. Bueno cuando varios PCs necesitan comunicarse entre si.

### Modo server

Todos solo con el host. Bueno para Minecraft o juegos donde el mundo/servidor real esta en una maquina concreta.

### Propuesta

Antes de crear la LAN, alguien propone:

```text
create server
```

o:

```text
create red
```

Los demas pueden ponerse listos o quedarse en lobby.

### SessionId

Identificador de la LAN activa, por ejemplo:

```text
LAN-F723
```

Sirve para que todos sepan que hablan de la misma sesion LAN. En v5.5.4 tambien se usa internamente para filtrar trafico: un peer solo deberia recibir paquetes LAN si su estado pertenece al `SessionId` activo.

### IP virtual

IP dentro de la LAN virtual, normalmente dentro de:

```text
10.88.0.0/16
```

Ejemplos:

```text
10.88.152.64
10.88.112.184
10.88.0.50
```

---

## Requisitos

- Windows.
- Permisos de administrador para crear/configurar Wintun.
- `wintun.dll` junto al ejecutable o copiado al output.
- SDK/runtime compatible con el `TargetFramework` del proyecto.
- Firewall permitiendo UDP/QUIC en los puertos configurados.

Valores por defecto:

```text
UDP discovery/control/fallback : 51888
QUIC datos Wintun              : 51889
MTU                            : 1280
PAK                            : 1280
BST                            : 16
Prefijo virtual                : 10.88.0.0/16
Trackers publicos              : activados por defecto
```

---

## Instalacion y compilacion

### Restaurar y compilar

Desde la carpeta del proyecto:

```powershell
dotnet restore
dotnet build -c Release
```

### Publicar para Windows x64

```powershell
dotnet publish -c Release -r win-x64
```

Si se quiere publicar autocontenido:

```powershell
dotnet publish -c Release -r win-x64 --self-contained true
```

> Nota: si tu SDK no soporta el framework configurado en `QuicLan.csproj`, ajusta el SDK o el `TargetFramework` segun tu entorno.

### Ejecutar como administrador

Lo normal es ejecutar QuicLAN como administrador. Si no lo haces, el programa puede intentar relanzarse elevado, salvo que uses:

```powershell
--no-elevate
```

---

## Uso rapido

Ejecuta:

```powershell
QuicLan.exe
```

Te pedira:

```text
Nombre visible:
Sala:
```

Ejemplo:

```text
Nombre visible: Pedro Minecraft
Sala: survival-amigos-2026
```

Con eso ya entras al lobby. La LAN no se activa automaticamente.

Si quieres hacerlo por flags:

```powershell
QuicLan.exe --name "Pedro Minecraft" --room "survival-amigos-2026"
```

---

## Las 4 ventanas

QuicLAN v5.5.x esta pensado como un mini panel 2x2 en Windows Terminal o varias ventanas CMD.

```text
┌─────────────────────────┬─────────────────────────┐
│ 1. Control              │ 2. Estado / Lobby       │
│ comandos                │ lista viva de usuarios  │
├─────────────────────────┼─────────────────────────┤
│ 3. Logs / Diagnostico   │ 4. Chat de lobby        │
│ eventos y errores       │ mensajes humanos        │
└─────────────────────────┴─────────────────────────┘
```

### CMD 1: Control

Es la terminal principal. Sirve para escribir comandos.

Ejemplos:

```text
create server
create red
ready
start
lobby
ip 10.88.0.50
stat
help
quit
```

### CMD 2: Estado / Lobby

Muestra el estado vivo:

- Nombre local.
- Sala.
- Si hay LAN activa.
- Modo: red o server.
- Host/coordinador.
- Propuesta activa.
- Usuarios.
- IP virtual de cada uno.
- Estado: lobby, listo, en LAN, reconectando.
- Transporte control/datos.
- Contadores.

### CMD 3: Logs / Diagnostico

Muestra eventos:

- Trackers usados.
- Peers detectados.
- Propuestas recibidas.
- Cambios de estado.
- Intentos QUIC.
- Fallos QUIC.
- Uso de fallback UDP.
- Errores Wintun/firewall/red.

### CMD 4: Chat

Chat simple de lobby. Sirve para coordinarse:

```text
Pedro: yo hosteo, tengo el mundo
Ana: espera que doy ready
Carlos: dale start
```

El chat pertenece a la sala/lobby, no a la LAN. Puedes estar en lobby y seguir hablando.

---

## Flujo normal de uso

### Caso 1: crear server para Minecraft

En PC de Pedro:

```text
Nombre visible: Pedro
Sala: survival123
```

Pedro escribe:

```text
create server
```

A los demas les aparece la propuesta. Ana escribe:

```text
ready
```

Pedro inicia:

```text
start
```

Resultado:

```text
LAN activa: SERVER
Host: Pedro
Ana entra a LAN
Los no listos siguen en lobby
```

Los clientes conectan al host usando la IP virtual que aparece en el panel de lobby.

### Caso 2: crear red completa

Alguien escribe:

```text
create red
```

Los que quieran entrar:

```text
ready
```

El creador:

```text
start
```

Resultado:

```text
LAN activa: RED
Todos los que entraron intentan conectarse entre todos
```

### Caso 3: entrar tarde

Luis entra a la misma sala cuando ya hay LAN activa.

El lobby le muestra:

```text
Hay LAN activa: SERVER
Host: Pedro
```

Luis puede escribir:

```text
ready
```

o:

```text
s
```

Si entra, QuicLAN intenta conectarlo a la LAN existente.

---

## Modo lobby

El lobby es el estado base. En lobby:

- No necesitas activar Wintun para participar en la sala.
- Puedes ver a otros usuarios.
- Puedes hablar por chat.
- Puedes ver propuestas.
- Puedes elegir IP custom antes de entrar.
- Puedes esperar sin entrar a LAN.
- Puedes volver a lobby sin salir de la sala.

Comando para volver a lobby:

```text
lobby
```

o:

```text
n
```

---

## Modo red

Modo red significa:

```text
Todos los participantes dentro de la LAN intentan hablar con todos.
```

Ventajas:

- Bueno para apps donde todos necesitan verse entre si.
- Bueno para juegos/protocolos LAN peer-to-peer.
- Permite que cada enlace pueda tener ajustes distintos en el futuro.

Desventajas:

- Consume mas conexiones.
- Con muchos usuarios puede ser mas pesado.
- No siempre hace falta si solo hay un servidor central.

Comando:

```text
create red
```

Alias soportados:

```text
red
network
mesh
create network
```

---

## Modo server

Modo server significa:

```text
Todos ven el lobby, pero en la LAN los clientes se conectan principalmente al host.
```

Ideal para:

- Minecraft.
- Juegos con un host claro.
- Servicios locales en un PC concreto.
- Reducir conexiones innecesarias.

Comando:

```text
create server
```

Alias soportados:

```text
server
host
hostear
```

Regla importante:

```text
En modo server, el host/coordinador manda la sesion LAN.
Los clientes pueden entrar o quedarse en lobby.
```

---

## Propuestas de LAN

Antes de iniciar la LAN, se crea una propuesta.

Ejemplo:

```text
create server
```

Eso no activa directamente la LAN. Crea algo como:

```text
Pedro propone crear LAN modo SERVER
SessionId: LAN-F723
```

Los demas pueden escribir:

```text
ready
```

El creador inicia:

```text
start
```

Mientras hay una propuesta activa, no deberia crearse otra propuesta distinta. Si alguien quiere cambiar, primero se cancela:

```text
cancel
```

El estado de propuesta/LAN se reenvia periodicamente como snapshot para que un peer que perdio un paquete de control pueda volver a converger con el resto de la sala.

---

## Sistema de listo / no listo

### Marcar listo

```text
ready
```

Alias:

```text
s
si
listo
lan
join
unirme
```

Significado:

```text
Quiero entrar a la propuesta actual o a la LAN activa.
```

### Quitar listo o salir de LAN

```text
lobby
```

Alias:

```text
n
no
notready
no-listo
salir-lan
leave lan
```

Significado:

```text
No quiero estar en LAN ahora. Me quedo en la sala/lobby.
```

Si eres host de una LAN server y sales, la LAN server se cierra y la sala queda viva.

---

## IPs virtuales

QuicLAN usa IPs virtuales dentro del prefijo configurado, por defecto:

```text
10.88.0.0/16
```

Cada usuario necesita una IP unica dentro de la LAN activa.

Ejemplo:

```text
Pedro  10.88.152.64
Ana    10.88.112.184
Carlos 10.88.0.50
```

Reglas de diseño:

- Antes de activar LAN, puedes ajustar tu IP.
- Una vez dentro de LAN, tu IP queda congelada.
- Un usuario nuevo debe elegir/recibir una IP libre.
- No se cambia la IP de los que ya estan dentro de LAN para acomodar a un nuevo.

---

## IP custom

Puedes pedir una IP concreta:

```text
ip 10.88.0.50
```

Regla:

```text
Primero que reserva una IP custom, se la queda.
```

Ejemplo:

```text
Ana reserva 10.88.0.50
Carlos entra despues y tambien quiere 10.88.0.50
Resultado: Carlos debe cambiar
```

Si la IP esta ocupada o reservada, el programa debe avisar:

```text
Esa IP ya esta ocupada/reservada. Mira el panel de lobby para ver quien la tiene.
```

---

## Reconexiones y fantasmas

Si alguien se cae, cambia de WiFi o cierra mal el programa, QuicLAN deberia mostrar estados como:

```text
RECONECTANDO
DESCONECTADO
```

La idea de diseno es:

- La sala no muere porque alguien caiga.
- Si el usuario vuelve con la misma identidad, puede reclamar su nombre/IP.
- Si el host cae en modo server, los demas vuelven o permanecen en lobby.
- Si el host vuelve, se puede crear una nueva LAN o reconectar segun estado.

En v5.5.4 ya existe parte del estado `RECONECTANDO`, pero la gestion perfecta de fantasmas/reclamacion persistente de identidad todavia es una zona a seguir endureciendo.

---

## Transporte: UDP, QUIC y fallback

Una confusion normal: QuicLAN **siempre usa UDP** para algunas cosas.

### UDP se usa para

- Discovery inicial.
- Hello de sala.
- STUN.
- Trackers.
- Mensajes de control.
- Estado de lobby.
- Chat.
- Fallback de datos cifrado cuando QUIC no esta disponible o no se permite usarlo todavia.

### QUIC se usa para

- Datos unicast de la LAN cuando el enlace QUIC esta abierto.
- Broadcast/multicast por fanout hacia peers concretos cuando ya existe enlace QUIC con esos peers.
- Transporte preferido para paquetes Wintun hacia un peer concreto.

### Por que en el panel aparece UDP

Si ves algo como:

```text
Control/Datos: UDP/QUIC...
```

significa:

```text
Control = UDP
Datos   = QUIC intentando conectar
```

Estados posibles:

```text
UDP/QUIC          control por UDP, datos por QUIC
UDP/QUIC...       control por UDP, QUIC intentando
UDP/UDP fallback  control por UDP, datos por fallback UDP cifrado
UDP/UDP           QUIC desactivado, todo por UDP cifrado cuando aplica
local             este PC
```

No pasa nada porque el control vaya por UDP. Eso es normal. Lo importante para rendimiento es si los **datos LAN** acaban en QUIC o en fallback UDP. En broadcast/multicast, QuicLAN replica el paquete peer por peer; cada envio puede usar QUIC si existe enlace o fallback UDP cifrado si esta permitido.

---

## Trackers y discovery

QuicLAN busca peers de varias formas:

1. Broadcast LAN local.
2. Candidates conocidos.
3. STUN para saber endpoint publico.
4. Trackers UDP publicos.

Trackers por defecto:

```text
udp://tracker.opentrackr.org:1337/announce
udp://open.demonii.com:1337/announce
udp://open.stealth.si:80/announce
udp://tracker.torrent.eu.org:451/announce
udp://tracker.srv00.com:6969/announce
udp://tracker.qu.ax:6969/announce
udp://tracker.dler.org:6969/announce
udp://tracker.theoks.net:6969/announce
```

Para desactivar trackers:

```powershell
QuicLan.exe --name "Pedro" --room "sala" --no-trackers
```

Para agregar tracker:

```powershell
QuicLan.exe --name "Pedro" --room "sala" --tracker udp://mi-tracker:6969/announce
```

Si quieres usar solo trackers personalizados y no los publicos por defecto, combina `--no-trackers` con uno o varios `--tracker`:

```powershell
QuicLan.exe --name "Pedro" --room "sala" --no-trackers --tracker udp://mi-tracker:6969/announce
```

Los trackers deberian verse principalmente en el panel de logs, no saturar la terminal principal.

---

## Comandos de la terminal principal

### Basicos

```text
help                muestra ayuda
stat                estado resumido
peers               alias de stat
quit                cerrar
exit                cerrar
salir               cerrar
```

### Lobby / LAN

```text
create server       propone una LAN modo SERVER/host
create red          propone una LAN modo RED completa
ready               marcar listo o unirse a LAN activa
s                   alias corto de ready
start               iniciar la LAN propuesta si tu la creaste
cancel              cancelar tu propuesta activa
lobby               salir de LAN o quitar listo sin salir de sala
n                   alias corto de lobby/no listo
reset lobby         limpiar estado local de lobby/propuesta
```

### IP

```text
ip 10.88.0.50       reservar IP custom
```

### Ajustes rapidos

```text
pak 1000            cambia limite de paquete overlay/IP
bst 16              cambia rafaga interna
mtu 1200            cambia MTU virtual
reset               vuelve a valores seguros
```

Valores validos:

```text
mtu: 576-1400
pak: 576-1400
bst: 1-256
```

---

## Flags de arranque

Uso interactivo:

```powershell
QuicLan.exe
```

Uso directo:

```powershell
QuicLan.exe --name "Pedro" --room "mi-sala-secreta-larga"
```

Opciones:

```text
--room <texto>           sala/clave compartida
--name <nombre>          nombre visible obligatorio
--adapter <nombre>       nombre del adaptador Wintun
--port <udp>             puerto UDP discovery/control/fallback
--data-port <udp>        puerto QUIC de datos
--mtu <bytes>            MTU virtual
--pak <bytes>            limite de paquete overlay/IP
--bst <n>                rafaga interna
--prefix <ipv4>          red virtual /16
--no-trackers            no usar trackers publicos
--tracker <url>          agregar tracker UDP
--verbose                diagnostico extra
--no-elevate             no relanzar como administrador
--disable-quic           desactivar QUIC
--no-udp-data-fallback   no usar fallback UDP para datos si QUIC no esta listo
--help                   ayuda
```

Nota: `--disable-quic` y `--no-udp-data-fallback` no se pueden usar juntos, porque entonces no quedaria ningun transporte para los datos IP de la LAN.

Ejemplos:

```powershell
QuicLan.exe --name "Pedro" --room "survival-amigos-2026"
QuicLan.exe --name "Ana" --room "survival-amigos-2026" --no-trackers
QuicLan.exe --name "Carlos" --room "survival-amigos-2026" --disable-quic
QuicLan.exe --name "Luis" --room "survival-amigos-2026" --port 52000 --data-port 52001
```

---

## Ajustes principales

### MTU

Tamaño maximo aproximado de paquete IP virtual.

```text
mtu 1200
```

Default:

```text
1280
```

### PAK

Limite de paquete overlay/IP.

```text
pak 1000
```

Default:

```text
1280
```

### BST

Burst interno de envio.

```text
bst 16
```

Default:

```text
16
```

### Recomendacion

Para uso normal, no tocar nada. QuicLAN viene con valores seguros por defecto.

---

## Seguridad

Modelo de seguridad resumido:

- La sala funciona como secreto compartido.
- Los Hellos se cifran usando clave derivada de la sala.
- Cada peer tiene identidad criptografica.
- Los mensajes relevantes van autenticados/cifrados por el protocolo.
- QUIC usa certificado generado desde la identidad del peer.
- El fallback UDP no es texto plano: es cifrado.

Importante:

```text
Quien conoce la sala puede intentar entrar al lobby.
```

QuicLAN v5.5.4 prioriza simplicidad: no hay todavia una allowlist fuerte de amigos, permisos avanzados o invitaciones firmadas obligatorias.

Recomendaciones:

- Usa salas largas y privadas.
- No uses `default`, `1234`, `minecraft`, etc.
- No compartas la sala en publico.
- Si usas una sala corta, cualquiera que la adivine podria intentar aparecer.

---

## Arquitectura interna

En v5.5.4 el proyecto esta concentrado en pocos archivos grandes, separados por responsabilidad principal:

```text
Program.cs               arranque, opciones, constantes, nodo principal
ControlCoordination.cs   lobby, propuestas, ready/start/cancel, control packets
LanTunnel.cs             Wintun, adaptador, IP virtual, paquetes LAN
TransportOverlay.cs      UDP overlay, Hello, discovery, fallback, packet codec
QuicTransport.cs         QUIC real, certificados, conexiones, streams
ConsolePanels.cs         4 paneles: control, lobby, logs, chat via pipes
QuicLan.csproj           proyecto .NET
wintun.dll               driver/biblioteca Wintun
```

### Flujo simplificado

```text
Usuario inicia QuicLAN
  -> escribe nombre y sala
  -> se deriva clave de sala
  -> se carga/crea identidad local
  -> se crea IP virtual
  -> se abre UDP discovery/control
  -> se configuran paneles
  -> entra al lobby
  -> discovery encuentra peers
  -> se intercambian estados de lobby
  -> alguien propone server/red
  -> peers dan ready
  -> start crea LAN activa
  -> paquetes Wintun se enrutan por QUIC o UDP fallback
```

---

## Paneles internos

El usuario ejecuta un solo `.exe`. El proceso principal abre los otros paneles automaticamente.

Internamente se usan argumentos privados como:

```text
--quiclan-panel
--pipe
```

No estan pensados para uso manual. Sirven para que el proceso padre abra ventanas hijas y se comuniquen por Named Pipes.

---

## Troubleshooting

### Veo `SÃ³lo`, `TÃº` o texto raro

En v5.5.4 se intento evitar usando textos ASCII y fijando UTF-8. Si vuelve a pasar:

- Usa Windows Terminal en vez de CMD clasico.
- Ejecuta `chcp 65001` antes de abrir.
- Evita textos con tildes en mensajes del programa.

### Pongo la misma sala y no veo a mi amigo

Revisa:

- Misma sala exacta.
- Firewall de Windows.
- Ambos con Internet.
- Ambos usando trackers o ambos en la misma LAN local.
- Puerto UDP permitido.
- Logs de tracker/discovery en CMD 3.

### Veo al peer pero no entra a LAN

Recuerda:

```text
Ver a alguien en lobby no significa estar en LAN.
```

Debe existir propuesta y alguien debe iniciar:

```text
create server
ready
start
```

### Veo UDP y esperaba QUIC

Normal. UDP siempre se usa para control. Mira la parte de datos:

```text
UDP/QUIC          datos por QUIC
UDP/QUIC...       intentando QUIC
UDP/UDP fallback  datos por fallback UDP
```

Si nunca pasa a QUIC:

- Firewall puede bloquear `data-port`.
- NAT puede impedir entrada QUIC.
- Prueba port-forwarding.
- Revisa logs de QUIC.
- Asegurate de no usar `--disable-quic`.

### No puedo cambiar IP

Si ya estas en LAN activa, la IP queda congelada. Sal a lobby:

```text
lobby
```

Luego intenta:

```text
ip 10.88.0.50
```

### La IP esta ocupada

El primero que la reserva gana. Elige otra IP.

### Se abren demasiadas ventanas

Por diseno v5.5.x abre 3 paneles adicionales. En futuras versiones podria haber modo simple 2 ventanas o modo compacto.

### El host cae

En modo server, si el host cae, los demas deberian volver/seguir en lobby y decidir si esperar o crear una nueva LAN.

### Wintun falla

Revisa:

- Ejecutar como administrador.
- `wintun.dll` junto al exe.
- Antivirus/firewall.
- Que no haya otra instancia usando el mismo adaptador.

---

## Preguntas frecuentes

### ¿La sala activa directamente la LAN?

No. La sala crea lobby. La LAN se activa solo con propuesta + ready + start.

### ¿Puedo estar en sala sin estar en LAN?

Si. Esa es la idea principal.

### ¿En modo server veo a todos?

Si, en el lobby puedes ver a todos. Pero en la LAN real los clientes se conectan principalmente al host.

### ¿En modo server los clientes se conectan entre ellos?

No deberian necesitarlo para datos LAN. El objetivo es que cada cliente hable con el host.

### ¿En modo red todos se conectan con todos?

Si, esa es la idea.

### ¿Por que hay chat si ya tengo Discord?

Porque el chat ayuda a coordinar sin salir de la sala: quien hostea, quien esta listo, quien cambia IP, etc.

### ¿Puedo usar nombre con espacios?

Si. El nombre visible debe ser humano, no el nombre del PC.

### ¿Puedo usar IP fija/custom?

Si:

```text
ip 10.88.0.50
```

### ¿Que pasa si dos quieren la misma IP custom?

Gana el primero que la reservo. El otro debe cambiar.

### ¿UDP significa inseguro?

No necesariamente. En QuicLAN, UDP se usa como transporte, pero los paquetes/control van protegidos por el protocolo.

### ¿QUIC reemplaza UDP?

No del todo. QUIC se usa para datos LAN hacia peers concretos cuando puede, incluyendo broadcast/multicast despues de replicarlo por peer. UDP sigue siendo necesario para discovery, control y fallback.

---

## Limitaciones conocidas

- No hay relay propio todavia. NATs muy duros pueden impedir conexiones directas.
- QUIC puede no conectar detras de algunos routers sin port-forwarding o reglas de firewall.
- QUIC DATAGRAM todavia no esta implementado; se usa QUIC stream fiable.
- No hay sistema completo de permisos/allowlist.
- La identidad existe, pero la gestion perfecta de reclamar nombre/IP tras caidas todavia puede endurecerse.
- Los ajustes por peer completos tipo `set 2 pak 120` son parte del diseno, pero no estan totalmente cerrados en esta version.
- El allocator central perfecto de IPs por host/coordinador todavia puede mejorarse.
- Los paneles estan basados en procesos/Named Pipes y pueden comportarse diferente segun consola/terminal.
- Es una version experimental: conviene probar con amigos antes de confiar en ella para sesiones largas.

---

## Roadmap sugerido

### v5.5.x inmediata

- Pulir bugs de lobby/propuesta.
- Hacer que el CMD padre sea todavia mas limpio.
- Mejorar logs humanos.
- Mejorar render del panel de lobby sin parpadeo.
- Mostrar mejor host/coordinador y SessionId.
- Separar mas claro `Control` vs `Datos`.

### v5.6

- Ajustes por peer completos:

```text
set 2 pak 120
set 2 mtu 1100
set 2 transport udp
```

- Negociacion de ajustes por pareja.
- Panel de detalles por peer.
- Estado de perdida/RTT/throughput por peer.

### v5.7

- Allocator central de IPs mas robusto.
- Reclamacion de IP por identidad.
- Expiracion limpia de fantasmas.
- Modo reconnect mas fuerte.

### v5.8

- Relay opcional para NAT duro/CGNAT.
- Mejor NAT traversal QUIC.
- Posible QUIC DATAGRAM.

### Futuro

- Invitaciones opcionales.
- Allowlist opcional.
- UI TUI compacta en una sola ventana.
- Perfil Minecraft/server.
- Perfil red completa.

---

## Glosario

### BST

Burst interno. Cuantos paquetes se intentan procesar en rafaga.

### Candidate

Direccion posible donde puede estar un peer.

### Discovery

Proceso de encontrar peers de la misma sala.

### Fallback UDP

Modo de datos por UDP cifrado cuando QUIC no esta listo o no funciona.

### Host

Usuario central en modo server.

### LAN activa

Sesion de red virtual ya iniciada.

### Lobby

Sala previa donde la gente se ve y se organiza.

### MTU

Tamano maximo de paquete IP virtual.

### PAK

Limite de paquete overlay/IP usado por QuicLAN.

### Peer

Otro usuario/nodo de la sala.

### QUIC

Transporte moderno sobre UDP usado para datos unicast cuando conecta correctamente.

### Room / Sala

Texto compartido que identifica el grupo.

### SessionId

ID de la LAN activa, por ejemplo `LAN-F723`.

### Tracker

Servidor externo que ayuda a descubrir otros peers de la misma sala.

### Wintun

Adaptador virtual usado para crear la red IP en Windows.

---

## Resumen corto para usuarios

```text
1. Abre QuicLAN.
2. Escribe nombre visible.
3. Escribe sala.
4. Mira el lobby.
5. Si quieres hostear Minecraft: create server.
6. Tus amigos escriben ready.
7. Tu escribes start.
8. Todos los listos entran a la LAN.
9. Los demas pueden quedarse en lobby y unirse despues.
```

---

## Resumen tecnico corto

```text
QuicLAN = sala/lobby por UDP cifrado + Wintun + LAN session + QUIC datos + UDP fallback.

UDP siempre existe para discovery/control/chat/trackers.
QUIC se usa para datos LAN hacia peers concretos cuando el link esta abierto.
Broadcast/multicast se replica peer por peer y puede usar QUIC o fallback UDP cifrado.
El lobby no equivale a LAN.
La LAN es una sesion dentro de la sala.
```
