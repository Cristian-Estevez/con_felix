# Outline:
    ### Automated Security Auditing Tool:
        Develop a script that scans a network or system for common security
        vulnerabilities like open ports, outdated software versions, weak passwords, etc.
        You can use tools like Nmap or Metasploit framework for scanning and scripting languages 
        like Python or Bash for automation.


# Ideas:
    - scanear todos los puertos:
        - listar servicios que encuentra
        - analisis de versiones de servicios
        - escaneo liviano
        - escaneo profundo (de acuerdo a los resultado encontrados)

    - agregar configuraciones usuario
        - (Por flags o prompt)
        - Rangos de puertos
        - Puerto específico
        - Servicio específico
        - Puertos más conocidos

    - output:
        - a txt.
        - opcional 
        - modos output (formato, pasarle ruta de output)

    - Archivo de config
        - pensar y desarrollar
        - armar un template por defecto

# Notas Felix:
## Pensar en tecnicas de evasion para la no deteccion:
## Fragmentacion de paquetes
## Escaneos aleatorios
## Tiempos de espera variables


