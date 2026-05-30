# Attack Simulation: TOR Usage

These are the steps taken to simulate a bad actor installing and using TOR on the corporate
workstation, generating the logs and IoCs used in the threat hunt.

## Steps

1. **Download the TOR browser installer**
   - URL: [https://www.torproject.org/download/](https://www.torproject.org/download/)

2. **Install silently (portable)**
   ```
   tor-browser-windows-x86_64-portable-15.0.14.exe /S
   ```

3. **Open TOR Browser** from the folder on the Desktop

4. **Connect to TOR and browse .onion sites**
   - Use a site like [https://onion.live/](https://onion.live/) to find active .onion links

5. **Create a suspicious file on the Desktop**
   - Create a file named `tor-shopping-list.txt`
   - Add a few fake illicit items as content

6. **Delete the file**

## IoCs Generated

| IoC | Type | Source |
|---|---|---|
| `Tor Browser.lnk` | File artifact | Desktop shortcut |
| `tor-shopping-list.txt` | File artifact | User-created suspicious file |
| `firefox.exe` from Desktop path | Process | TOR Browser engine (not standard install path) |
| `tor.exe` → `203.55.81.1:9001` | Network | External TOR relay connection |
| `firefox.exe` → `127.0.0.1:9150` | Network | Local SOCKS proxy connection |
