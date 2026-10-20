# IPv4 Subnet Calculator

A modern, responsive, client-side IPv4 Subnet Calculator built with pure **HTML5**, **CSS3**, and **JavaScript** (no dependencies or frameworks required).

## Features

- **Instant Subnet Calculations**:
  - Network Address
  - Broadcast Address
  - Subnet Mask & Wildcard Mask
  - Usable Host Range (First & Last Host)
  - Total Addresses & Usable Host Count
  - Handles `/31` Point-to-Point links ([RFC 3021](https://datatracker.ietf.org/doc/html/rfc3021)) and `/32` single host routes cleanly
- **IP Scope & Class Detection**:
  - Automatically identifies Private (RFC 1918), Public, Loopback, Link-Local (APIPA), CGNAT (RFC 6598), Multicast, and Reserved ranges.
  - Class A, B, C, D, and E detection.
  - Reverse DNS (`.in-addr.arpa`) and Hexadecimal representation.
- **Interactive Controls**:
  - Synchronized CIDR slider (`/0` to `/32`) and dropdown selector.
  - Smart IP parser: paste formats like `192.168.1.1/24` directly into the IP field.
  - Quick-preset chips for common networking scenarios (Home LAN, Large Corporate, VPC, Point-to-point).
- **Color-Coded Binary Visualizer**:
  - Visual breakdown of the 32 bits showing **Network bits** and **Host bits** distinctly.
- **Subnet Subdivider**:
  - Split any network into smaller subnets with a real-time table of child subnet allocations.
- **Dark / Light Mode**:
  - System-aware theme toggle with persistent preference stored in `localStorage`.
- **One-Click Copy**:
  - Quick-copy buttons with animated toast feedback.

## How to Run

Simply open `index.html` in any web browser:

```bash
# On Linux:
xdg-open index.html

# Or start a quick local HTTP server:
python3 -m http.server 8080
```
Then visit `http://localhost:8080` in your browser.
