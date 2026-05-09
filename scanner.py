import nmap
import argparse
import json
import os
from datetime import datetime


def perform_scan(target):
    print(f"[*] Démarrage du scan sur la cible : {target}")

    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=target, arguments='-sS -sV -T4')
    except nmap.PortScannerError as e:
        print(f"[-] Erreur Nmap : {e}")
        return None
    except Exception as e:
        print(f"[-] Erreur inattendue : {e}")
        return None

    scan_results = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "hosts": []
    }

    for host in nm.all_hosts():
        host_info = {
            "ip": host,
            "state": nm[host].state(),
            "protocols": {}
        }

        for proto in nm[host].all_protocols():
            host_info["protocols"][proto] = []
            lport = nm[host][proto].keys()

            for port in sorted(lport):
                port_data = nm[host][proto][port]
                port_info = {
                    "port": port,
                    "state": port_data['state'],
                    "service": port_data['name'],
                    "version": port_data['version']
                }
                host_info["protocols"][proto].append(port_info)

        scan_results["hosts"].append(host_info)

    return scan_results


def generate_json_report(data, output_dir="reports"):
    if not data:
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/audit_report_{timestamp}.json"

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

    print(f"[+] Rapport JSON généré avec succès : {filename}")


def generate_html_report(data, output_dir="reports"):
    if not data:
        return

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/audit_report_{timestamp}.html"

    # Structure HTML et CSS
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport d'Audit Réseau</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f4f7f6; color: #333; }}
            .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
            .container {{ margin: 20px auto; max-width: 900px; }}
            .summary {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            .host {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; border-left: 5px solid #3498db; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background-color: #ecf0f1; }}
            .state-open {{ color: #e74c3c; font-weight: bold; }}
            .state-filtered {{ color: #f39c12; font-weight: bold; }}
            .state-closed {{ color: #7f8c8d; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ Rapport d'Audit Réseau (SOC / Blue Team)</h1>
        </div>
        <div class="container">
            <div class="summary">
                <h2>Résumé du Scan</h2>
                <p><strong>Cible scannée :</strong> {data['target']}</p>
                <p><strong>Date d'exécution :</strong> {data['scan_time']}</p>
            </div>
    """

    for host in data['hosts']:
        html_content += f"""
            <div class="host">
                <h3>Machine : {host['ip']} (Statut: {host['state'].upper()})</h3>
                <table>
                    <tr>
                        <th>Port / Protocole</th>
                        <th>État</th>
                        <th>Service</th>
                        <th>Version détectée</th>
                    </tr>
        """
        for proto, ports in host['protocols'].items():
            for port_info in ports:
                # Appliquer une classe CSS selon l'état du port
                state_class = f"state-{port_info['state']}"
                version_display = port_info['version'] if port_info['version'] else "<em>Non détectée</em>"

                html_content += f"""
                    <tr>
                        <td>{port_info['port']} / {proto.upper()}</td>
                        <td class="{state_class}">{port_info['state'].upper()}</td>
                        <td>{port_info['service']}</td>
                        <td>{version_display}</td>
                    </tr>
                """
        html_content += """
                </table>
            </div>
        """

    html_content += """
        </div>
    </body>
    </html>
    """

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[+] Rapport HTML généré avec succès : {filename}")


def main():
    parser = argparse.ArgumentParser(description="Outil d'Audit Réseau Automatisé (Blue Team/SOC)")
    parser.add_argument("-t", "--target", required=True, help="Adresse IP ou sous-réseau cible (ex: 192.168.1.0/24)")

    args = parser.parse_args()

    print("-" * 50)
    print("      AUTOMATED NETWORK SECURITY AUDIT TOOL")
    print("-" * 50)

    results = perform_scan(args.target)

    if results:
        generate_json_report(results)
        generate_html_report(results)


if __name__ == "__main__":
    main()