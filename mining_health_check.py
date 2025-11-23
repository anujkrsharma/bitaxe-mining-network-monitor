#!/usr/bin/env python3
import json
import subprocess
import re
import sys
import time
import signal
from datetime import timedelta, datetime
import os # Import os module
from dotenv import load_dotenv # Import load_dotenv

# Clear the screen once at the very beginning
os.system('clear')

# Load environment variables from .env file
load_dotenv()

BITCOIN_NODE_IP = os.getenv('BITCOIN_NODE_IP')
BITCOIN_NODE_RPCU = os.getenv('BITCOIN_RPC_USER')
BITCOIN_NODE_RPCP = os.getenv('BITCOIN_RPC_PASSWORD')

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.box import MINIMAL
from rich.text import Text
from rich.columns import Columns
import re

console = Console(force_terminal=True) # Force terminal rendering for styles

def run_command_for_grep(command):
    """
    Runs a shell command specifically for grep, handling its exit codes.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            return result.stdout
        elif result.returncode == 1:
            return ""
        else:
            return f"Error running command: {command}\nStderr: {result.stderr}"
    except Exception as e:
        return f"Unexpected error running command: {e}"

def run_command(command):
    """Runs a general shell command and returns its output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running command: {e}\nStderr: {e.stderr}"

def get_bitcoin_node_status():
    """Checks the Bitcoin Node sync status."""
    command = f"ssh ubuntu@{BITCOIN_NODE_IP} \"sudo su - btc -c '/snap/bitcoin-core/190/bin/bitcoin-cli -rpcuser={BITCOIN_NODE_RPCU} -rpcpassword={BITCOIN_NODE_RPCP} getblockchaininfo'\""
    output = run_command(command)
    if "Error" in output:
        return {"error": output}
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": f"Failed to decode JSON from bitcoin-cli: {output}"}

def get_bitcoin_node_log():
    """Checks the Bitcoin Node debug log for errors and provides a summary."""
    command = f"ssh ubuntu@{BITCOIN_NODE_IP} \"sudo su - btc -c 'tail -n 1000 /home/btc/snap/bitcoin-core/common/.bitcoin/debug.log | grep -i error'\""
    output = run_command_for_grep(command)
    if "Error" in output:
        return output, False
    
    errors = [line for line in output.splitlines() if line.strip()]
    if errors:
        return f"{len(errors)} errors found. Example: {errors[0][:100]}...", False
    return "No errors found.", True

def get_ckpool_status():
    """Checks the ckpool service status."""
    command = f"ssh ubuntu@{BITCOIN_NODE_IP} \"sudo systemctl status ckpool.service\""
    return run_command(command)

def get_ckpool_log():
    """Checks the ckpool logs for errors and provides a summary."""
    command = f"ssh ubuntu@{BITCOIN_NODE_IP} \"sudo journalctl -u ckpool.service -n 1000 | grep -i error\""
    output = run_command_for_grep(command)
    if "Error" in output:
        return output, False

    errors = [line for line in output.splitlines() if line.strip()]
    if errors:
        recent_errors = [e for e in errors if "Nov 2025" in e]
        if recent_errors:
            return f"{len(recent_errors)} recent errors found. Example: {recent_errors[0][:100]}...", False
        else:
            return f"{len(errors)} old errors found. No recent errors.", True
    return "No errors found.", True

def get_bitaxe_miner_info_by_ip(ip):
    """Fetches info from a Bitaxe Miner API by IP address."""
    command = f"curl http://{ip}/api/system/info"
    output = run_command(command)
    if "Error" in output:
        return {"error": output}
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": f"Failed to decode JSON from Bitaxe Miner API: {output}"}

def get_mempool_info():
    """Checks the Bitcoin Node mempool information."""
    command = f"ssh ubuntu@{BITCOIN_NODE_IP} \"sudo su - btc -c '/snap/bitcoin-core/190/bin/bitcoin-cli -rpcuser={BITCOIN_NODE_RPCU} -rpcpassword={BITCOIN_NODE_RPCP} getmempoolinfo'\""
    output = run_command(command)
    if "Error" in output:
        return {"error": output}
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": f"Failed to decode JSON from mempool info: {output}"}

def get_peer_info():
    """Checks the Bitcoin Node peer information."""
    command = f"ssh ubuntu@{BITCOIN_NODE_IP} \"sudo su - btc -c '/snap/bitcoin-core/190/bin/bitcoin-cli -rpcuser={BITCOIN_NODE_RPCU} -rpcpassword={BITCOIN_NODE_RPCP} getpeerinfo'\""
    output = run_command(command)
    if "Error" in output:
        return {"error": output}
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return {"error": f"Failed to decode JSON from peer info: {output}"}

def get_ckpool_stats_from_log():
    """Fetches and parses the ckpool.log file for additional stats."""
    command = f"ssh ubuntu@{BITCOIN_NODE_IP} \"sudo tail -n 100 /home/ckpool/solobtc/logs/ckpool.log\""
    output = run_command(command)
    if "Error" in output:
        return {"error": f"Could not read ckpool.log: {output}"}

    stats = {}
    
    try:
        lines = output.strip().split('\n')
        
        # Find the latest lines with pool stats
        user_worker_line = None
        hashrate_line = None
        shares_line = None

        for line in reversed(lines):
            if '"Users"' in line and not user_worker_line:
                user_worker_line = line
            elif '"hashrate5m"' in line and not hashrate_line:
                hashrate_line = line
            elif '"accepted"' in line and not shares_line:
                shares_line = line
            
            if user_worker_line and hashrate_line and shares_line:
                break
        
        if user_worker_line:
            json_str = user_worker_line.split('Pool:')[1]
            data = json.loads(json_str)
            stats['Total Users'] = data.get('Users')
            stats['Workers'] = data.get('Workers')

        if hashrate_line:
            json_str = hashrate_line.split('Pool:')[1]
            data = json.loads(json_str)
            stats['Hashrate (5min)'] = data.get('hashrate5m')

        if shares_line:
            json_str = shares_line.split('Pool:')[1]
            data = json.loads(json_str)
            stats['Shares Accepted'] = data.get('accepted')
            stats['Shares Rejected'] = data.get('rejected')

    except Exception as e:
        return {"error": f"Failed to parse ckpool.log: {e}"}
        
    return {k: str(v) for k, v in stats.items() if v is not None}

def get_wallet_balance():
    """Fetches the balance of the ckpool reward wallet."""
    address = os.getenv('CKPOOL_REWARD_WALLET_ADDRESS')
    command = f"curl 'https://blockchain.info/balance?active={address}'"
    output = run_command(command)
    if "error" in output.lower():
        return {"error": output}
    try:
        data = json.loads(output)
        balance_satoshi = data[address]['final_balance']
        balance_btc = balance_satoshi / 100_000_000
        return {"balance_btc": balance_btc, "address": address}
    except (json.JSONDecodeError, KeyError) as e:
        return {"error": f"Failed to parse balance response: {e}, output: {output}"}

def get_miner_ips_from_ckpool_log():
    """Parses the ckpool.log to find unique worker IP addresses from lines containing 'bitaxe'."""
    command = f"ssh ubuntu@{BITCOIN_NODE_IP} \"sudo grep -ai bitaxe /home/ckpool/solobtc/logs/ckpool.log\""
    output = run_command_for_grep(command) # Using grep-specific function
    if "Error" in output:
        return []

    # Regex to find an IP address on a line
    ip_pattern = re.compile(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")
    
    found_ips = ip_pattern.findall(output)
    
    # Return a list of unique IPs
    return sorted(list(set(found_ips)))

def print_summary(health_summary, summary_data):
    """Prints the final health summary using rich tables and panels."""
    col1_renderables = []
    col2_renderables = []

    summary_table = Table(title=None, box=MINIMAL, show_header=False)
    summary_table.add_column("Component", style="bold")
    summary_table.add_column("Status")

    overall_status = "Good"
    for component, status in health_summary.items():
        color = "green" if status == "Good" else "yellow" if status == "Warning" else "red"
        summary_table.add_row(component.replace('_', ' ').title(), f"[{color}]{status}[/]")
        if status != "Good":
            overall_status = "Warning"
    col1_renderables.append(summary_table)

    overall_color = "green" if overall_status == "Good" else "yellow" if overall_status == "Warning" else "red"
    col2_renderables.append(Text.from_markup(f"\n[bold]Overall Network Health:[/bold] [{overall_color}]{overall_status}[/]"))
    
    if summary_data:
        total_hashrate_ghs = sum(m.get('hash_rate_ghs', 0) for m in summary_data.get('miners', []))
        sync_status = summary_data.get('btc_sync_status', 'N/A')
        ckpool_users = summary_data.get('ckpool_users', 'N/A')
        wallet_balance = summary_data.get('wallet_balance_btc')
        wallet_address = summary_data.get('wallet_address')

        summary_text = (
            f"Bitcoin node is {sync_status}. "
            f"ckpool has {ckpool_users} users. "
            f"Total miner hashrate is {total_hashrate_ghs:.2f} GH/s."
        )
        col2_renderables.append(Text(summary_text))

        if wallet_address is not None:
             col2_renderables.append(Text(f"Wallet Address: {wallet_address}"))
        if wallet_balance is not None:
            wallet_balance_color = "green" if wallet_balance > 0 else "default"
            col2_renderables.append(Text.from_markup(f"Wallet Balance: [{wallet_balance_color}]{wallet_balance:.8f} BTC[/]"))
    else:
        if overall_status == "Good":
            col2_renderables.append(Text("All components are operating as expected."))
        else:
            col2_renderables.append(Text("One or more components have warnings. Please review the detailed report above."))

    console.print(Panel(
        Columns([
            Panel(Group(*col1_renderables), title="Component Status", expand=True, title_align="left"),
            Panel(Group(*col2_renderables), title="Overall Health Summary", expand=True, title_align="left")
        ]),
        title="[bold green]Status and Health Summary[/bold green]",
        title_align="left"
    ))


def get_temp_color(temp):
    """Determines the color for temperature display based on its value."""
    if temp < 60:
        return "green"
    elif 60 <= temp <= 61:
        return "yellow"
    else:
        return "red"

def generate_report():
    """Generates the health report by fetching data from all components."""
    health_summary = {}
    report_renderables = []
    summary_data = {}
    summary_data['miners'] = []

    # 1. Bitcoin Node & ckpool
    col1_content = []
    col2_content = []
    node_health = "Good"
    node_status = get_bitcoin_node_status()
    if "error" in node_status:
        col1_content.append(Text.from_markup(f"[bold red]Error fetching status:[/bold red] {node_status['error']}"))
        node_health = "Error"
        summary_data['btc_sync_status'] = "Error"
    else:
        initial_download = node_status.get('initialblockdownload')
        progress = node_status.get('verificationprogress', 0) * 100
        summary_data['btc_sync_status'] = 'Synced' if not initial_download else f"Syncing ({progress:.2f}%)"

        node_table = Table(box=None, show_header=False, show_edge=False)
        node_table.add_column("Metric", style="bold")
        node_table.add_column("Value")
        sync_status_text = f"{ 'Synced' if not initial_download else 'Syncing'} ({progress:.8f}% complete, initial download: {'yes' if initial_download else 'no'})"
        sync_status_color = "green" if progress > 99.999 else "red"
        node_table.add_row("Sync Status", f"[{sync_status_color}]{sync_status_text}[/]")
        node_table.add_row("Current Block Height", str(node_status.get('blocks')))
        node_table.add_row("Current Difficulty", str(node_status.get('difficulty')))
        col1_content.append(node_table)
        if initial_download:
            node_health = "Warning"

    node_log_summary, node_log_ok = get_bitcoin_node_log()
    col1_content.append(Text.from_markup(f"[bold] Debug Log:[/bold] {node_log_summary}"))
    if not node_log_ok:
        node_health = "Warning"
    
    peer_info = get_peer_info()
    if "error" in peer_info:
        col1_content.append(Text.from_markup(f"[bold red] Error fetching peer info:[/bold red] {peer_info['error']}"))
        node_health = "Warning"
    else:
        col1_content.append(Text.from_markup(f"[bold] Peer Information:[/bold] Connected to {len(peer_info)} peers."))
    
    health_summary['bitcoin_node'] = node_health
    
    # ckpool
    ckpool_health = "Good"
    ckpool_status_raw = get_ckpool_status()
    active_line = next((line for line in ckpool_status_raw.split('\n') if 'Active:' in line), None)
    if active_line and 'active (running)' in active_line:
        col1_content.append(Text.from_markup(f"\n[bold] ckpool Service Status:[/bold] {active_line.strip()}"))
    else:
        col1_content.append(Text.from_markup("\n[bold red] ckpool Service Status:[/bold red] Could not determine status or not running."))
        ckpool_health = "Error"
    
    ckpool_log_summary, ckpool_log_ok = get_ckpool_log()
    col1_content.append(Text.from_markup(f"[bold] ckpool Logs for Errors:[/bold] {ckpool_log_summary}"))
    if not ckpool_log_ok:
        ckpool_health = "Warning"

    dashboard_info = get_ckpool_stats_from_log()
    if "error" in dashboard_info:
        col1_content.append(Text.from_markup(f"[bold red] Log Stats Error:[/bold red] {dashboard_info['error']}"))
        ckpool_health = "Warning"
        summary_data['ckpool_users'] = 'N/A'
    else:
        summary_data['ckpool_users'] = dashboard_info.get('Total Users', 'N/A')
        dashboard_table = Table(box=MINIMAL, show_header=False)
        dashboard_table.add_column("Metric", style="bold")
        dashboard_table.add_column("Value")
        if dashboard_info:
             for key, value in dashboard_info.items():
                dashboard_table.add_row(key, value)
             col1_content.append(dashboard_table)

    health_summary['ckpool_service'] = ckpool_health




    mempool_info = get_mempool_info()
    if "error" not in mempool_info:
        mempool_table = Table(title="Mempool Information", box=MINIMAL)
        mempool_table.add_column("Metric", style="bold")
        mempool_table.add_column("Value")
        mempool_table.add_row("Loaded", str(mempool_info.get('loaded')))
        mempool_table.add_row("Transaction Count", str(mempool_info.get('size')))
        mempool_table.add_row("Memory Usage", f"{mempool_info.get('usage', 0) / 1024 / 1024:.2f} MB")
        mempool_table.add_row("Total Bytes", str(mempool_info.get('bytes')))
        mempool_table.add_row("Total Fee", f"{mempool_info.get('total_fee')} BTC")
        col2_content.append(mempool_table)

    wallet_balance_info = get_wallet_balance()
    if "error" not in wallet_balance_info:
        summary_data['wallet_balance_btc'] = wallet_balance_info.get('balance_btc')
        summary_data['wallet_address'] = wallet_balance_info.get('address')

    report_renderables.append(Panel(
        Columns([
            Panel(Group(*col1_content), expand=True, title="Node & ckpool Info", title_align="left"),
            Panel(Group(*col2_content), expand=True, title="Mempool", title_align="left")
        ]),
        title=f"[bold green]Bitcoin Node & ckpool ({BITCOIN_NODE_IP})[/bold green]",
        expand=True,
        title_align="left"
    ))

    # 2. Bitaxe Miners
    miner_ips = get_miner_ips_from_ckpool_log()
    miner_panels = []
    if not miner_ips:
        miner_panels.append(Panel(Text("No active miners found in ckpool log."), title="Miners", title_align="left"))
    else:
        for ip in miner_ips:
            miner_health = "Good"
            miner_info = get_bitaxe_miner_info_by_ip(ip)
            
            miner_table = Table(box=MINIMAL, show_header=False)
            miner_table.add_column("Metric", style="bold")
            miner_table.add_column("Value")

            if "error" in miner_info:
                miner_health = "Error"
                summary_data['miners'].append({'ip': ip, 'hash_rate': 0})
                miner_table.add_row("Status", "[bold red]Offline[/bold red]")
                miner_table.add_row("Hash Rate", "N/A")
                miner_table.add_row("Error Percentage", "N/A")
                miner_table.add_row("Shares Accepted", "N/A")
                miner_table.add_row("Shares Rejected", "N/A")
                miner_table.add_row("Uptime", "N/A")
                miner_table.add_row("Temperatures", "N/A")
                miner_table.add_row("Connection", "N/A")
                miner_table.add_row("Block Height", "N/A")
                miner_table.add_row("Network Difficulty", "N/A")
            else:
                miner_table.add_row("Status", "[bold green]Online[/bold green]")
                uptime = timedelta(seconds=miner_info.get('uptimeSeconds', 0))
                error_percentage = miner_info.get('errorPercentage', 0)
                hash_rate_ghs = miner_info.get('hashRate', 0)
                summary_data['miners'].append({'ip': ip, 'hash_rate_ghs': hash_rate_ghs})
                
                expected_hashrate = miner_info.get('expectedHashrate', 0)
                hash_rate_color = "green" if hash_rate_ghs >= expected_hashrate else "red"
                miner_table.add_row("Hash Rate", f"[{hash_rate_color}]{hash_rate_ghs:.2f} GH/s[/]")
                miner_table.add_row("Error Percentage", f"{error_percentage:.2f}%")
                miner_table.add_row("Shares Accepted", str(miner_info.get('sharesAccepted')))
                miner_table.add_row("Shares Rejected", str(miner_info.get('sharesRejected')))
                miner_table.add_row("Uptime", str(uptime))
                temp = miner_info.get('temp')
                vr_temp = miner_info.get('vrTemp')
                temp_color = get_temp_color(temp)
                vr_temp_color = get_temp_color(vr_temp)
                miner_table.add_row("Temperatures", f"temp: [{temp_color}]{temp}°C[/], vrTemp: [{vr_temp_color}]{vr_temp}°C[/]")
                miner_table.add_row("Connection", f"{miner_info.get('stratumURL')}:{miner_info.get('stratumPort')}")
                miner_table.add_row("Block Height", str(miner_info.get('blockHeight')))
                miner_table.add_row("Network Difficulty", str(miner_info.get('networkDifficulty')))
                
                if error_percentage > 5:
                    miner_health = "Warning"
                if hash_rate_ghs == 0:
                    miner_health = "Error"
            
            miner_content = Panel(miner_table, title=ip, title_align="left")
            miner_panels.append(miner_content)
            health_summary[f'bitaxe_miner_{ip}'] = miner_health

    report_renderables.append(Panel(
        Columns(miner_panels),
        title="[bold green]Bitaxe Miners[/bold green]",
        expand=True,
        title_align="left"
    ))
    return health_summary, report_renderables, summary_data


def shutdown_handler(signum, frame):
    """Handles SIGTERM and SIGINT for graceful shutdown."""
    # Here you would add logic to terminate any background processes.
    # For now, we just print a message and exit.
    console.print("[bold yellow]\nShutdown signal received. Exiting. Goodbye![/bold yellow]")
    sys.exit(0)

def main():
    """Main function to run all checks and print the report with rich formatting."""
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    # Initial setup
    os.system('clear')
    console.print(Panel(Text.from_markup("[bold green]Bitcoin Mining Network Status Report[/bold green]"), title_align="left"))
    health_summary, report_renderables, summary_data = {}, [], {}

    while True:
        # First iteration will just show the title and then fetch.
        # Subsequent iterations will have the previous report on screen.
        
        with console.status("[bold green]Fetching mining network status...[/bold green]", spinner="dots"):
            health_summary, report_renderables, summary_data = generate_report()

        # Clear the screen and display the newly fetched report
        os.system('clear')
        console.print(Panel(Text.from_markup("[bold green]Bitcoin Mining Network Status Report[/bold green]"), title_align="left"))
        for renderable in report_renderables:
            console.print(renderable)

        print_summary(health_summary, summary_data)
        
        # Countdown with loading animation
        for i in range(10, 0, -1):
            with console.status(f"[bold green]Next update in {i} seconds...[/bold green]", spinner="dots"):
                time.sleep(1)

if __name__ == "__main__":
    main()
