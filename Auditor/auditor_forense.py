# Importamos bibliotecas necesarias
import os
import json
import subprocess
import argparse
import logging
import hashlib
import sys
import locale
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

# Configuración del logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("auditoria.log"),
                        logging.StreamHandler(sys.stdout)
                    ])

class WindowsForensicsAuditor:
    def __init__(self, config_file="config.json"):
        """
        Inicializa la clase con la ruta del archivo de configuración.
        """
        self.config_file = config_file
        self.results_dir = "forensic_results"
        self._check_privileges()
        self._setup_directories()
        self.commands = self._load_commands()
        self.report_summary = {}
        self.all_errors = []

    def _get_os_locale(self):
        """
        Detecta el idioma del sistema operativo.
        """
        try:
            return locale.getlocale()[0]
        except (ValueError, IndexError):
            return "en_US"

    def _adjust_commands_for_locale(self, commands, os_locale):
        """
        Ajusta los comandos según el idioma del sistema.
        """
        if os_locale and os_locale.startswith("es"): # Español
            commands['users_info'] = [
                "net users",
                "net localgroup Administradores",
                "net group Administradores",
                "wmic rdtoggle list",
                "wmic useraccount list",
                "wmic group list",
                "wmic netlogin get name,lastlogin,badpasswordcount",
                "wmic netclient list brief",
                "wmic nicconfig get",
                "wmic netuse get"
            ]
        return commands

    def _load_commands(self):
        """
        Carga y ajusta los comandos desde el archivo de configuración.
        """
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                commands = json.load(f)
            
            os_locale = self._get_os_locale()
            return self._adjust_commands_for_locale(commands, os_locale)
        except FileNotFoundError:
            logging.error(f"Error: El archivo de configuración '{self.config_file}' no fue encontrado.")
            sys.exit(1)
        except json.JSONDecodeError:
            logging.error(f"Error: El archivo de configuración '{self.config_file}' no es un JSON válido.")
            sys.exit(1)

    def _check_privileges(self):
        """
        Verifica si el script se está ejecutando con permisos de administrador.
        """
        try:
            is_admin = (os.getuid() == 0) # Linux/macOS
        except AttributeError:
            try:
                import ctypes
                is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0) # Windows
            except ImportError:
                is_admin = False
        
        if not is_admin:
            logging.warning("El script no se está ejecutando con permisos de administrador. "
                            "Algunos comandos pueden fallar por falta de privilegios.")
            input("Presione Enter para continuar de todos modos o cierre la ventana para salir...")

    def _setup_directories(self):
        """
        Crea los directorios para guardar los resultados si no existen.
        """
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
            logging.info(f"Directorio de resultados '{self.results_dir}' creado.")

    def _execute_command(self, command):
        """
        Ejecuta un comando del sistema y captura su salida.
        """
        try:
            logging.info(f"Ejecutando comando: '{command}'")
            salida = subprocess.check_output(command, shell=True, text=True, 
                                             encoding="utf-8", errors="ignore", 
                                             stderr=subprocess.STDOUT)
            return {"output": salida, "status": "success"}
        except subprocess.CalledProcessError as e:
            error_msg = f"Comando fallido: '{command}' - Error: {e.returncode} - Mensaje: {e.output.strip()}"
            logging.error(error_msg)
            self.all_errors.append({"command": command, "message": e.output.strip()})
            return {"output": f"Error al ejecutar el comando: {command}\n{e.output}", "status": "error"}
        except Exception as e:
            error_msg = f"Error inesperado al ejecutar el comando: '{command}' - {e}"
            logging.error(error_msg)
            self.all_errors.append({"command": command, "message": str(e)})
            return {"output": f"Error inesperado: {e}", "status": "error"}

    def run_category(self, category):
        """
        Ejecuta todos los comandos de una categoría específica.
        """
        if category not in self.commands:
            logging.error(f"Categoría '{category}' no encontrada en el archivo de configuración.")
            return

        logging.info(f"Iniciando la auditoría para la categoría: '{category}'")
        
        results = {}
        success_count = 0
        error_count = 0
        for command in self.commands[category]:
            result = self._execute_command(command)
            results[command] = result["output"]
            if result["status"] == "success":
                success_count += 1
            else:
                error_count += 1
        
        self.report_summary[category] = {
            "total_commands": len(self.commands[category]),
            "success_count": success_count,
            "error_count": error_count
        }
        self.save_results(category, results)
        logging.info(f"Auditoría de la categoría '{category}' completada.")

    def save_results(self, category, data):
        """
        Guarda los resultados de la auditoría en un archivo JSON y calcula su hash.
        """
        filename = os.path.join(self.results_dir, f"{category}_results.json")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            
            with open(filename, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            logging.info(f"Resultados de '{category}' guardados en '{filename}'")
            logging.info(f"HASH SHA256 para el archivo: {file_hash}")
        except Exception as e:
            logging.error(f"Error al guardar los resultados para '{category}': {e}")

    def run_all(self):
        """
        Ejecuta todos los comandos de todas las categorías.
        """
        for category in self.commands:
            self.run_category(category)
        
        self.generate_report()
    
    def load_existing_results(self):
        """
        Carga todos los archivos JSON de resultados existentes para generar el reporte.
        """
        report_data = {}
        self.report_summary = {}
        self.all_errors = []
        
        for filename in os.listdir(self.results_dir):
            if filename.endswith("_results.json"):
                category = filename.replace("_results.json", "")
                filepath = os.path.join(self.results_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        report_data[category] = data
                        
                        total_commands = len(data)
                        error_count = sum(1 for output in data.values() if output.startswith("Error al ejecutar el comando"))
                        success_count = total_commands - error_count
                        
                        self.report_summary[category] = {
                            "total_commands": total_commands,
                            "success_count": success_count,
                            "error_count": error_count
                        }

                        # Extrae los errores de los datos cargados
                        for command, output in data.items():
                            if output.startswith("Error al ejecutar el comando"):
                                self.all_errors.append({"command": command, "message": output})
                            
                except json.JSONDecodeError:
                    logging.error(f"Error al leer el archivo JSON: {filepath}")
        
        return report_data
    
    def generate_report(self, report_data=None):
        """
        Genera el reporte final en formato HTML.
        """
        if report_data is None:
            report_data = self.load_existing_results()

        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('report_template.html')

        output_file = os.path.join(self.results_dir, "reporte_auditoria.html")
        
        html_report = template.render(
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            report_summary=self.report_summary,
            all_errors=self.all_errors,
            report_data=report_data
        )

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        logging.info(f"Reporte HTML generado en '{output_file}'")

    def run_interface(self):
        """
        Interfaz de usuario profesional en la terminal.
        """
        while True:
            print("\n" + "="*50)
            print("  HERRAMIENTA DE AUDITORÍA FORENSE DE WINDOWS")
            print("="*50)
            print("\nSeleccione una opción:")
            print("1. Ejecutar una auditoría completa")
            print("2. Generar un reporte de los resultados existentes")
            print("3. Salir")
            
            choice = input("\nIngrese su opción: ")

            if choice == "1":
                self.run_all()
            elif choice == "2":
                self.generate_report()
            elif choice == "3":
                print("Saliendo de la herramienta. ¡Hasta pronto!")
                sys.exit(0)
            else:
                print("Opción no válida. Por favor, intente de nuevo.")


if __name__ == "__main__":
    auditor = WindowsForensicsAuditor()
    auditor.run_interface()