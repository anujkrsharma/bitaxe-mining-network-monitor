# Bitaxe Mining Network Monitor

This project provides a real-time health and status monitor for a local Bitcoin mining setup. It gathers information from your Bitcoin Node, ckpool, and all connected Bitaxe Miners, presenting it in a clear, dashboard-like command-line interface.

## Features

*   **Bitcoin Node Status:** Monitors sync status, block height, difficulty, mempool information, and peer connections.
*   **ckpool Status:** Checks service health, log for errors, and displays mining statistics (users, workers, hashrate, shares).
*   **Mempool Status:** Checks service health, log for errors, and displays current mempool status.
*   **Bitaxe Miner Monitoring:** Automatically discovers and reports detailed information from connected Bitaxe miners, including hash rate, temperatures, uptime, and error rates.
*   **Wallet Balance:** Displays the balance of your configured ckpool reward wallet.
*   **Rich CLI Output:** Utilizes the `rich` library for a visually appealing and organized terminal output.
*   **Real-time Updates:** Refreshes the display every 10 seconds.

## Prerequisites

Before running this monitor, ensure you have the following:

*   **Python 3.x** installed.
*   **SSH access** to your Bitcoin Node machine with `ubuntu` user and passwordless `sudo` for `btc` user.
*   Your Bitcoin Node, ckpool, and Bitaxe Miners are running and accessible on your local network.

## Setup

Follow these steps to get the Bitcoin Mining Monitor up and running:

1.  **Clone the Repository (or download the files):**

    ```bash
    git clone https://github.com/your-username/bitcoin-mining-monitor.git
    cd bitcoin-mining-monitor
    ```

2.  **Create and Activate a Virtual Environment (Recommended):**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Assumptions:**

    bitcoin node location - [ BITCOIN_NODE_IP] /home/btc/snap/bitcoin-core
    
6.  **Configure Environment Variables:**

    Create a `.env` file in the root directory of the project based on the `.env.example` file.

    ```bash
    cp .env.example .env
    ```

    Open the newly created `.env` file and fill in your specific details:

    ```
    # Bitcoin Node Configuration
    BITCOIN_NODE_IP=YOUR_BITCOIN_NODE_IP        # e.g., 192.168.1.1
    BITCOIN_RPC_USER=YOUR_RPC_USERNAME          # e.g., btc
    BITCOIN_RPC_PASSWORD=YOUR_RPC_PASSWORD      # e.g., XXXXXXX
    CKPOOL_REWARD_WALLET_ADDRESS=YOUR_CKPOOL_REWARD_WALLET_ADDRESS # e.g., bc1q...
    ```

    *   `YOUR_BITCOIN_NODE_IP`: The IP address of your Bitcoin Node.
    *   `YOUR_RPC_USERNAME`: The RPC username for your Bitcoin Node.
    *   `YOUR_RPC_PASSWORD`: The RPC password for your Bitcoin Node.
    *   `YOUR_CKPOOL_REWARD_WALLET_ADDRESS`: The Bitcoin address of your ckpool reward wallet.

## Usage

To run the Bitcoin Mining Monitor, execute the `mining_health_check.py` script:

```bash
python3 mining_health_check.py
```

The script will display a real-time report in your terminal, updating every 10 seconds.

## Troubleshooting

*   **`ssh` connection issues:** Ensure your `BITCOIN_NODE_IP` is correct and that you can `ssh` into your Bitcoin Node machine from where you are running the script. Verify SSH keys or password authentication.
*   **`bitcoin-cli` errors:** Check `BITCOIN_RPC_USER` and `BITCOIN_RPC_PASSWORD` in your `.env` file. Ensure `bitcoin-cli` is correctly installed and accessible on your Bitcoin Node machine.
*   **`ckpool` service not found/running:** Verify that `ckpool` is properly installed and running as a systemd service on your Bitcoin Node.
*   **`curl` errors for Bitaxe Miners:** Ensure your Bitaxe Miners are powered on, connected to the network, and their API endpoint (`http://MINER_IP/api/system/info`) is accessible.
*   **`rich` rendering issues:** Ensure your terminal supports rich text and colors.

<img width="1824" height="946" alt="517963799-266a0fba-9721-4a60-ad04-9ff77dad5cd2" src="https://github.com/user-attachments/assets/db86bc55-b5d9-4338-a561-aeb0ab969872" />

